####################
# HCC runtime (HSA implementation)
####################
if (HAS_ROCM EQUAL 1)
add_mcwamp_library_hsa(mcwamp_hsa mcwamp_hsa.cpp unpinned_copy_engine.cpp)
add_mcwamp_library_hc_am(hc_am hc_am.cpp)
install(TARGETS mcwamp_hsa hc_am
    EXPORT hcc-targets
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    )
MESSAGE(STATUS "ROCm available, going to build HSA HCC Runtime")
else (HAS_ROCM EQUAL 1)
MESSAGE(STATUS "ROCm NOT available, NOT going to build HSA HCC Runtime")
endif (HAS_ROCM EQUAL 1)


option(CODE_OBJ_MANAGER_LIB "Enable the code object manager" ON)
if (CODE_OBJ_MANAGER_LIB)
  set(CODE_OBJ_MANAGER_DIR "/home/scchan/code/support/lib")
  target_include_directories(mcwamp_hsa PRIVATE ${CODE_OBJ_MANAGER_DIR}/comgr/include)
  target_link_libraries(mcwamp_hsa PRIVATE ${CODE_OBJ_MANAGER_DIR}/build.comgr/libcomgr.so)
endif (CODE_OBJ_MANAGER_LIB)

####################
# CodeXL Activity Logger Library
####################
if (USE_CODEXL_ACTIVITY_LOGGER EQUAL 1)
if (CODEXL_ACTIVITY_LOGGER_LIBRARY)
  target_link_libraries(mcwamp_hsa PRIVATE ${CODEXL_ACTIVITY_LOGGER_LIBRARY}/libCXLActivityLogger.so)
  target_link_libraries(hc_am ${CODEXL_ACTIVITY_LOGGER_LIBRARY}/libCXLActivityLogger.so)
endif (CODEXL_ACTIVITY_LOGGER_LIBRARY)
endif (USE_CODEXL_ACTIVITY_LOGGER EQUAL 1)
