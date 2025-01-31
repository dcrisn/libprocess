
add_executable( test_subprocess
   main_test_subprocess.cpp
)

target_include_directories( test_subprocess PUBLIC
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/>
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/src/include/>
	$<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/tests/>
)
	
target_link_libraries( test_subprocess PRIVATE
    tarp::process
    asio
)
