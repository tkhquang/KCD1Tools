/**
 * @file render/mask_material.cpp
 * @brief The materials outline copies are drawn with.
 */

#include "render/mask_material.hpp"
#include "aob_resolver.hpp"
#include "constants.hpp"
#include "rtti_types.hpp"
#include "engine/engine_env.hpp"
#include "engine/seh.hpp"

#include <DetourModKit.hpp>

#include <windows.h>

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace HenrySenses
{
    namespace
    {
        using GetterFn = std::uintptr_t(__fastcall *)(std::uintptr_t self);
        using RefFn = void(__fastcall *)(std::uintptr_t self);
        using LoadXmlFromFileFn = std::uintptr_t *(__fastcall *)(std::uintptr_t utils,
                                                                 std::uintptr_t *out,
                                                                 const char *file,
                                                                 bool reuse);
        using LoadXmlFromBufferFn = std::uintptr_t *(__fastcall *)(std::uintptr_t utils,
                                                                   std::uintptr_t *out,
                                                                   const char *buffer,
                                                                   std::size_t size,
                                                                   bool reuse);
        using NodeChildCountFn = int(__fastcall *)(std::uintptr_t node);
        using NodeGetChildFn = std::uintptr_t *(__fastcall *)(std::uintptr_t node, std::uintptr_t *out, int index);
        using NodeFindChildFn = std::uintptr_t *(__fastcall *)(std::uintptr_t node,
                                                               std::uintptr_t *out,
                                                               const char *tag);
        using NodeSetAttrFn = void(__fastcall *)(std::uintptr_t node, const char *key, const char *value);
        using NodeGetAttrFn = const char *(__fastcall *)(std::uintptr_t node, const char *key);
        using LoadMaterialFromXmlFn =
            std::uintptr_t(__fastcall *)(std::uintptr_t manager, const char *name, std::uintptr_t *node);

        /// The fallback mask material XML: plain Illum, no alpha test, opacity filled from MASK_MATERIAL_OPACITY.
        constexpr std::string_view DEFAULT_MASK_XML_FORMAT =
            R"(<Material Shader="Illum" Diffuse="1,1,1" Opacity="{}"/>)";
        constexpr std::size_t MATERIAL_NAME_MAX = 260;
        // A material has a handful of sub-materials. More than this is not a material file.
        constexpr int SUB_MATERIALS_MAX = 64;

        /**
         * @struct NodeApi
         * @brief The validated CXmlNode methods the conversion calls.
         */
        struct NodeApi
        {
            std::uintptr_t child_count{0};
            std::uintptr_t get_child{0};
            std::uintptr_t find_child{0};
            std::uintptr_t set_attr{0};
            std::uintptr_t get_attr{0};
            std::uintptr_t release{0};
        };

        /**
         * @struct CacheEntry
         * @brief One source material's mask, or the record that it did not convert.
         */
        struct CacheEntry
        {
            std::uintptr_t mask{0};
            bool converted{false};
        };

        std::unordered_map<std::uintptr_t, CacheEntry> s_cache;
        // Whether a (model, material) pair needs an outline copy.
        std::map<std::pair<std::uintptr_t, std::uintptr_t>, bool> s_copy_needed;
        // A render mesh has a handful of chunks. More than this is not a chunk array.
        constexpr std::uint32_t RENDER_CHUNKS_MAX = 256;
        std::uintptr_t s_default_mask = 0;
        bool s_default_failed = false;
        int s_builds_left = 0;
        bool s_pending = false;
        // Makes this load's mask names unique, so a new load never refills a material a render list still holds.
        std::uint32_t s_name_tag = 0;

        /** @brief Reads one engine field, or std::nullopt on a failed read. */
        template <typename T> [[nodiscard]] std::optional<T> read_field(std::uintptr_t address) noexcept
        {
            const auto value = DMK::memory::read<T>(DMK::Address{address});
            return value ? std::optional<T>{*value} : std::nullopt;
        }

        /** @brief The element count of an engine DynArray, kept in the u32 before its first element. */
        [[nodiscard]] std::uint32_t dyn_array_count(std::uintptr_t elements) noexcept
        {
            if (elements == 0)
            {
                return 0;
            }
            return read_field<std::uint32_t>(elements - sizeof(std::uint32_t)).value_or(0) &
                   constants::DYN_ARRAY_COUNT_MASK;
        }

        /**
         * @brief The shader item a chunk of material slot @p slot draws with (CMatInfo::GetShaderItem(int), vtable
         *        slot 19), or 0 where the engine falls back to its default material.
         */
        [[nodiscard]] std::uintptr_t chunk_shader_item(std::uintptr_t material, std::uint32_t slot) noexcept
        {
            const std::uintptr_t subs =
                read_field<std::uintptr_t>(material + constants::MAT_INFO_SUB_MTLS_OFFSET).value_or(0);
            const std::uint32_t count = dyn_array_count(subs);
            const std::uint32_t flags =
                read_field<std::uint32_t>(material + constants::MAT_INFO_FLAGS_OFFSET).value_or(0);
            if (count == 0 || (flags & constants::MTL_FLAG_MULTI_SUBMTL) == 0)
            {
                return material + constants::MAT_INFO_SHADER_ITEM_OFFSET;
            }
            if (slot >= count)
            {
                return 0;
            }
            const std::uintptr_t sub = read_field<std::uintptr_t>(subs + 8u * slot).value_or(0);
            return sub != 0 ? sub + constants::MAT_INFO_SHADER_ITEM_OFFSET : 0;
        }

        /**
         * @brief Reports whether a shader item draws and lacks the CustomRenderPass technique, as EF_AddEf and
         *        EF_BatchFlags see it. A shader item that draws nothing never needs a copy.
         */
        [[nodiscard]] bool shader_item_lacks_custom_pass(std::uintptr_t item) noexcept
        {
            const std::uintptr_t shader =
                read_field<std::uintptr_t>(item + constants::SHADER_ITEM_SHADER_OFFSET).value_or(0);
            const std::uintptr_t resources =
                read_field<std::uintptr_t>(item + constants::SHADER_ITEM_RESOURCES_OFFSET).value_or(0);
            const std::int32_t preprocess =
                read_field<std::int32_t>(item + constants::SHADER_ITEM_PREPROCESS_OFFSET).value_or(-1);
            if (shader == 0 || resources == 0 || preprocess == -1)
            {
                return false;
            }
            const std::uint32_t flags =
                read_field<std::uint32_t>(shader + constants::SHADER_FLAGS_OFFSET).value_or(constants::EF_NODRAW);
            const std::uint32_t flags2 =
                read_field<std::uint32_t>(shader + constants::SHADER_FLAGS2_OFFSET).value_or(constants::EF2_NODRAW);
            if ((flags & constants::EF_NODRAW) != 0 || (flags2 & constants::EF2_NODRAW) != 0)
            {
                return false;
            }
            const auto count = static_cast<std::int32_t>(
                read_field<std::uint32_t>(shader + constants::SHADER_TECHNIQUE_COUNT_OFFSET).value_or(0)
            );
            const std::uintptr_t techniques =
                read_field<std::uintptr_t>(shader + constants::SHADER_TECHNIQUES_OFFSET).value_or(0);
            const std::int32_t index =
                std::max(read_field<std::int32_t>(item + constants::SHADER_ITEM_TECHNIQUE_OFFSET).value_or(0), 0);
            if (count <= 0 || techniques == 0 || index >= count)
            {
                return true;
            }
            const std::uintptr_t technique =
                read_field<std::uintptr_t>(techniques + 8u * static_cast<std::uint32_t>(index)).value_or(0);
            const std::int8_t custom =
                technique != 0
                    ? read_field<std::int8_t>(technique + constants::TECHNIQUE_CUSTOM_RENDER_OFFSET).value_or(-1)
                    : std::int8_t{-1};
            return custom <= 0;
        }

        /** @brief The uncached mesh_needs_mask_copy() test. */
        [[nodiscard]] bool compute_needs_copy(std::uintptr_t stat_obj, std::uintptr_t material) noexcept
        {
            const std::uintptr_t mesh =
                read_field<std::uintptr_t>(stat_obj + constants::STAT_OBJ_RENDER_MESH_OFFSET).value_or(0);
            if (mesh == 0)
            {
                return true;
            }
            const std::uintptr_t chunks =
                read_field<std::uintptr_t>(mesh + constants::RENDER_MESH_CHUNKS_OFFSET).value_or(0);
            const std::uint32_t count = std::min(dyn_array_count(chunks), RENDER_CHUNKS_MAX);
            for (std::uint32_t i = 0; i < count; ++i)
            {
                const std::uintptr_t chunk = chunks + constants::RENDER_CHUNK_STRIDE * i;
                if (read_field<std::uintptr_t>(chunk + constants::RENDER_CHUNK_RE_OFFSET).value_or(0) == 0)
                {
                    continue;
                }
                const std::uint16_t slot =
                    read_field<std::uint16_t>(chunk + constants::RENDER_CHUNK_MAT_ID_OFFSET).value_or(0);
                const std::uintptr_t item = chunk_shader_item(material, slot);
                if (item != 0 && shader_item_lacks_custom_pass(item))
                {
                    return true;
                }
            }
            return false;
        }

        /** @brief Calls a no-argument getter under SEH, or returns 0 on a fault. */
        [[nodiscard]] std::uintptr_t guarded_get(std::uintptr_t fn, std::uintptr_t self) noexcept
        {
            __try
            {
                return reinterpret_cast<GetterFn>(fn)(self);
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return 0;
            }
        }

        /** @brief Calls an AddRef or Release slot under SEH. */
        void guarded_ref(std::uintptr_t fn, std::uintptr_t self) noexcept
        {
            __try
            {
                reinterpret_cast<RefFn>(fn)(self);
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
            }
        }

        /** @brief Loads a file into a CXmlNode tree, or returns 0. The caller owns one reference. */
        [[nodiscard]] std::uintptr_t
        guarded_load_file(std::uintptr_t fn, std::uintptr_t utils, const char *file) noexcept
        {
            std::uintptr_t root = 0;
            __try
            {
                (void)reinterpret_cast<LoadXmlFromFileFn>(fn)(utils, &root, file, false);
                return root;
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return 0;
            }
        }

        /** @brief Parses a buffer into a CXmlNode tree, or returns 0. The caller owns one reference. */
        [[nodiscard]] std::uintptr_t
        guarded_load_buffer(std::uintptr_t fn, std::uintptr_t utils, const char *buffer, std::size_t size) noexcept
        {
            std::uintptr_t root = 0;
            __try
            {
                (void)reinterpret_cast<LoadXmlFromBufferFn>(fn)(utils, &root, buffer, size, false);
                return root;
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return 0;
            }
        }

        /**
         * @brief Turns one material node into its mask form: plain Illum at the mask opacity.
         * @details A node with an alpha test gets the mask alpha test.
         */
        void convert_node(const NodeApi &api, std::uintptr_t node)
        {
            const char *alpha_test = reinterpret_cast<NodeGetAttrFn>(api.get_attr)(node, "AlphaTest");
            const bool alpha_tested = alpha_test != nullptr && std::strtof(alpha_test, nullptr) > 0.0f;
            const auto set_attr = reinterpret_cast<NodeSetAttrFn>(api.set_attr);
            set_attr(node, "Shader", "Illum");
            set_attr(node, "GenMask", "0");
            set_attr(node, "StringGenMask", "");
            set_attr(node, "Opacity", constants::MASK_MATERIAL_OPACITY);
            if (alpha_tested)
            {
                set_attr(node, "AlphaTest", constants::MASK_MATERIAL_ALPHA_TEST);
            }
        }

        /**
         * @brief Converts the root material node and each node under its SubMaterials child.
         * @return The number of sub-materials converted, or -1 on a fault.
         */
        [[nodiscard]] int guarded_convert(const NodeApi &api, std::uintptr_t root) noexcept
        {
            __try
            {
                convert_node(api, root);
                std::uintptr_t subs = 0;
                (void)reinterpret_cast<NodeFindChildFn>(api.find_child)(root, &subs, "SubMaterials");
                if (subs == 0)
                {
                    return 0;
                }
                int converted = 0;
                const int count = reinterpret_cast<NodeChildCountFn>(api.child_count)(subs);
                for (int i = 0; i < count && i < SUB_MATERIALS_MAX; ++i)
                {
                    std::uintptr_t child = 0;
                    (void)reinterpret_cast<NodeGetChildFn>(api.get_child)(subs, &child, i);
                    if (child != 0)
                    {
                        convert_node(api, child);
                        reinterpret_cast<RefFn>(api.release)(child);
                        ++converted;
                    }
                }
                reinterpret_cast<RefFn>(api.release)(subs);
                return converted;
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return -1;
            }
        }

        /** @brief Creates a material from a node, which the callee releases. Returns the material or 0. */
        [[nodiscard]] std::uintptr_t
        guarded_load_material(std::uintptr_t fn, std::uintptr_t manager, const char *name, std::uintptr_t node) noexcept
        {
            std::uintptr_t ref = node;
            __try
            {
                return reinterpret_cast<LoadMaterialFromXmlFn>(fn)(manager, name, &ref);
            }
            __except (engine_fault_filter(GetExceptionCode()))
            {
                return 0;
            }
        }

        /** @brief The engine's XML front end (CSystem's CXmlUtils), RTTI-checked, or 0. */
        [[nodiscard]] std::uintptr_t xml_utils() noexcept
        {
            const std::uintptr_t system = genv_interface(constants::GENV_SYSTEM_OFFSET);
            if (system == 0)
            {
                return 0;
            }
            const auto utils =
                DMK::memory::read<std::uintptr_t>(DMK::Address{system + constants::SYSTEM_XML_UTILS_OFFSET});
            return utils && object_is(GameClass::XmlUtils, *utils) ? *utils : 0;
        }

        /** @brief The material manager (I3DEngine::GetMaterialManager), RTTI-checked, or 0. */
        [[nodiscard]] std::uintptr_t material_manager() noexcept
        {
            const std::uintptr_t engine = genv_interface(constants::GENV_3DENGINE_OFFSET);
            if (engine == 0 || !object_is(GameClass::ThreeDEngine, engine))
            {
                return 0;
            }
            const std::uintptr_t get_manager =
                read_vtable_slot(engine, constants::ENGINE_3D_VTABLE_GET_MATERIAL_MANAGER_OFFSET);
            const std::uintptr_t manager = get_manager != 0 ? guarded_get(get_manager, engine) : 0;
            return manager != 0 && object_is(GameClass::MatMan, manager) ? manager : 0;
        }

        /** @brief Releases a node the mod owns one reference to. */
        void release_node(std::uintptr_t node) noexcept
        {
            if (const std::uintptr_t release = read_vtable_slot(node, constants::XML_NODE_VTABLE_RELEASE_OFFSET))
            {
                guarded_ref(release, node);
            }
        }

        /**
         * @brief Makes a material from a node tree, keeps one reference to it and logs the result.
         * @param root The tree. Its reference passes to the engine.
         * @param name The new material's name.
         * @return The material, or 0.
         */
        [[nodiscard]] std::uintptr_t make_material(std::uintptr_t root, const std::string &name)
        {
            const std::uintptr_t manager = material_manager();
            const std::uintptr_t load = manager != 0 ? validated_vtable_slot(
                                                           manager,
                                                           constants::MAT_MAN_VTABLE_LOAD_FROM_XML_OFFSET,
                                                           AnchorId::MatManLoadFromXml
                                                       )
                                                     : 0;
            if (load == 0)
            {
                release_node(root);
                return 0;
            }
            const std::uintptr_t material = guarded_load_material(load, manager, name.c_str(), root);
            if (material == 0 || !object_is(GameClass::MatInfo, material))
            {
                return 0;
            }
            const std::uintptr_t add_ref = read_vtable_slot(material, constants::MAT_INFO_VTABLE_ADD_REF_OFFSET);
            if (add_ref == 0)
            {
                return 0;
            }
            guarded_ref(add_ref, material);
            return material;
        }

        /**
         * @brief Builds the fallback mask from DEFAULT_MASK_XML_FORMAT, once per reset.
         * @details The strings are built before the engine owns anything, so a failed allocation leaks nothing and
         *          leaves the next call free to retry.
         */
        [[nodiscard]] std::uintptr_t default_mask()
        {
            if (s_default_mask != 0 || s_default_failed)
            {
                return s_default_mask;
            }
            const std::string xml =
                std::vformat(DEFAULT_MASK_XML_FORMAT, std::make_format_args(constants::MASK_MATERIAL_OPACITY));
            const std::string name = std::format("henrysenses{}{:x}", constants::MASK_MATERIAL_SUFFIX, s_name_tag);
            s_default_failed = true;
            const std::uintptr_t utils = xml_utils();
            const std::uintptr_t parse = utils != 0 ? validated_vtable_slot(
                                                          utils,
                                                          constants::XML_UTILS_VTABLE_LOAD_FROM_BUFFER_OFFSET,
                                                          AnchorId::XmlLoadFromBuffer
                                                      )
                                                    : 0;
            const std::uintptr_t root = parse != 0 ? guarded_load_buffer(parse, utils, xml.data(), xml.size()) : 0;
            if (root != 0 && object_is(GameClass::XmlNode, root))
            {
                s_default_mask = make_material(root, name);
            }
            else if (root != 0)
            {
                release_node(root);
            }
            s_default_failed = s_default_mask == 0;
            (void)DMK::log().try_log(
                s_default_mask != 0 ? DMK::LogLevel::Info : DMK::LogLevel::Warning,
                "MaskMaterial: fallback mask {}",
                s_default_mask != 0 ? DMK::format::format_address(s_default_mask) : std::string("could not be made")
            );
            return s_default_mask;
        }

        /**
         * @brief Converts one source material into its mask material.
         * @details The source's .mtl is loaded again and every material node becomes plain Illum at the mask opacity.
         *          The result is created under a "_hsmask" name beside the source.
         * @return The mask, or 0 when the source does not convert.
         */
        [[nodiscard]] std::uintptr_t convert_source(std::uintptr_t source)
        {
            if (!object_is(GameClass::MatInfo, source))
            {
                return 0;
            }
            const auto name_ptr =
                DMK::memory::read<std::uintptr_t>(DMK::Address{source + constants::MAT_INFO_NAME_OFFSET});
            std::string name = name_ptr ? read_c_string(*name_ptr, MATERIAL_NAME_MAX) : std::string{};
            if (name.empty())
            {
                return 0;
            }
            if (name.size() > 4 && _stricmp(name.c_str() + name.size() - 4, ".mtl") == 0)
            {
                name.resize(name.size() - 4);
            }
            const std::uintptr_t utils = xml_utils();
            const std::uintptr_t load_file = utils != 0 ? validated_vtable_slot(
                                                              utils,
                                                              constants::XML_UTILS_VTABLE_LOAD_FROM_FILE_OFFSET,
                                                              AnchorId::XmlLoadFromFile
                                                          )
                                                        : 0;
            // Every string is built before the tree exists, so a failed allocation cannot leak the tree.
            const std::string file = name + ".mtl";
            const std::string mask_name = std::format("{}{}{:x}", name, constants::MASK_MATERIAL_SUFFIX, s_name_tag);
            const std::uintptr_t root = load_file != 0 ? guarded_load_file(load_file, utils, file.c_str()) : 0;
            if (root == 0)
            {
                (void)DMK::log().try_log(DMK::LogLevel::Debug, "MaskMaterial: '{}' did not load", file);
                return 0;
            }
            // A read-only node (binary XML) ignores setAttr.
            if (!object_is(GameClass::XmlNode, root))
            {
                (void)DMK::log().try_log(DMK::LogLevel::Debug, "MaskMaterial: '{}' is not an editable XML tree", file);
                release_node(root);
                return 0;
            }
            const NodeApi api{
                validated_vtable_slot(
                    root,
                    constants::XML_NODE_VTABLE_GET_CHILD_COUNT_OFFSET,
                    AnchorId::XmlNodeGetChildCount
                ),
                validated_vtable_slot(root, constants::XML_NODE_VTABLE_GET_CHILD_OFFSET, AnchorId::XmlNodeGetChild),
                validated_vtable_slot(root, constants::XML_NODE_VTABLE_FIND_CHILD_OFFSET, AnchorId::XmlNodeFindChild),
                validated_vtable_slot(root, constants::XML_NODE_VTABLE_SET_ATTR_OFFSET, AnchorId::XmlNodeSetAttr),
                validated_vtable_slot(root, constants::XML_NODE_VTABLE_GET_ATTR_OFFSET, AnchorId::XmlNodeGetAttr),
                read_vtable_slot(root, constants::XML_NODE_VTABLE_RELEASE_OFFSET),
            };
            if (api.child_count == 0 || api.get_child == 0 || api.find_child == 0 || api.set_attr == 0 ||
                api.get_attr == 0 || api.release == 0)
            {
                release_node(root);
                return 0;
            }
            const int sub_materials = guarded_convert(api, root);
            if (sub_materials < 0)
            {
                // The tree is in an unknown state after a fault, so it is left alone, not released.
                return 0;
            }
            const std::uintptr_t mask = make_material(root, mask_name);
            (void)DMK::log().try_log(
                mask != 0 ? DMK::LogLevel::Info : DMK::LogLevel::Warning,
                "MaskMaterial: {} -> {} ({} sub-material(s)){}",
                name,
                mask_name,
                sub_materials,
                mask != 0 ? "" : ": the material could not be made"
            );
            return mask;
        }
    } // namespace

    void begin_mask_material_tick() noexcept
    {
        s_builds_left = constants::MASK_MATERIAL_BUILDS_PER_TICK;
        s_pending = false;
    }

    std::uintptr_t mask_material_for(std::uintptr_t source) noexcept
    {
        if (!feature_ready(Feature::MaskMaterial))
        {
            return 0;
        }
        try
        {
            if (s_name_tag == 0)
            {
                s_name_tag = static_cast<std::uint32_t>(GetTickCount64()) | 1u;
            }
            if (source == 0)
            {
                return default_mask();
            }
            if (const auto known = s_cache.find(source); known != s_cache.end())
            {
                return known->second.converted ? known->second.mask : default_mask();
            }
            if (s_builds_left <= 0)
            {
                s_pending = true;
                return 0;
            }
            --s_builds_left;
            // The slot exists before the conversion takes a material reference, so no later step can drop it.
            CacheEntry &entry = s_cache[source];
            entry.mask = convert_source(source);
            entry.converted = entry.mask != 0;
            return entry.converted ? entry.mask : default_mask();
        }
        catch (...)
        {
            (void)DMK::log().log_noexcept(
                DMK::LogLevel::Error,
                "MaskMaterial: a mask material build failed (allocation)"
            );
            return 0;
        }
    }

    bool mesh_needs_mask_copy(std::uintptr_t stat_obj, std::uintptr_t material)
    {
        if (stat_obj == 0 || material == 0)
        {
            return false;
        }
        const std::pair key{stat_obj, material};
        if (const auto known = s_copy_needed.find(key); known != s_copy_needed.end())
        {
            return known->second;
        }
        const bool needed = compute_needs_copy(stat_obj, material);
        s_copy_needed.emplace(key, needed);
        if (needed)
        {
            const auto name_ptr = read_field<std::uintptr_t>(material + constants::MAT_INFO_NAME_OFFSET).value_or(0);
            (void)DMK::log().try_log(
                DMK::LogLevel::Debug,
                "MaskMaterial: '{}' draws a chunk without a CustomRenderPass technique; the object gets an outline copy",
                name_ptr != 0 ? read_c_string(name_ptr, MATERIAL_NAME_MAX) : std::string("?")
            );
        }
        return needed;
    }

    bool mask_materials_pending() noexcept
    {
        return s_pending;
    }

    void reset_mask_materials() noexcept
    {
        const auto release = [](std::uintptr_t material) noexcept
        {
            if (material == 0 || !object_is(GameClass::MatInfo, material))
            {
                return;
            }
            if (const std::uintptr_t fn = read_vtable_slot(material, constants::MAT_INFO_VTABLE_RELEASE_OFFSET))
            {
                guarded_ref(fn, material);
            }
        };
        for (const auto &[source, entry] : s_cache)
        {
            release(entry.mask);
        }
        s_cache.clear();
        s_copy_needed.clear();
        release(s_default_mask);
        s_default_mask = 0;
        s_default_failed = false;
        s_pending = false;
        s_name_tag = 0;
    }

} // namespace HenrySenses
