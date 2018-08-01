#pragma once

#include "raii_handle.hpp"
#include "comgr/amd_comgr.h"

#include <vector>
#include <mutex>
#include <unordered_map>
#include "hsa/hsa.h"

namespace hc2
{
    namespace
    {

        inline
        void throwing_amd_comgr_result_check(
            amd_comgr_status_t res,
            const std::string& file,
            const std::string& fn,
            int line) {
            if (res != AMD_COMGR_STATUS_SUCCESS) {
                throw std::runtime_error{
                    "Failed in file " + file + ", in function \"" + fn +
                    "\", on line " + std::to_string(line) + ", with error: " +
                    std::to_string(res)};
            }
        }

        using RAII_comgr_data =
            RAII_move_only_handle<
                amd_comgr_data_t,
                decltype(amd_comgr_release_data)*>;

        class kernel_metadata {
        };

        class code_object {
             
            using Kernel_metadata_table = std::unordered_map<
                std::string, kernel_metadata>;

            public:
                code_object(const char* blob, std::size_t n) {
                    throwing_amd_comgr_result_check(
                        amd_comgr_create_data(AMD_COMGR_DATA_KIND_RELOCATABLE, &handle(data_)),
                        __FILE__,
                        __func__,
                        __LINE__);
                    throwing_amd_comgr_result_check(
                        amd_comgr_set_data(handle(data_), n, blob),
                        __FILE__,
                        __func__,
                        __LINE__);
                    throwing_amd_comgr_result_check(
                        amd_comgr_set_data_name(handle(data_), nullptr),
                        __FILE__,
                        __func__,
                        __LINE__);
                }

                const Kernel_metadata_table& get_kernel_metadata_table() {
                             return kernel_metadata_table;
                }

                code_object(code_object&& c) = default;
                code_object(const code_object&) = delete;
                ~code_object() = default;
            private:
                RAII_comgr_data data_ = {{}, amd_comgr_release_data};
                Kernel_metadata_table kernel_metadata_table;
        };

        class code_object_manager {
            public:
                code_object_manager() = default;
                ~code_object_manager() = default;
                void add_code_object(const char* blob, std::size_t n) {
                  objects.push_back(std::move(code_object(blob, n)));
                }
            private:
                std::vector<code_object> objects;
        };
    }
}
