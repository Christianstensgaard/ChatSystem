# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.22

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:

#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:

# Disable VCS-based implicit rules.
% : %,v

# Disable VCS-based implicit rules.
% : RCS/%

# Disable VCS-based implicit rules.
% : RCS/%,v

# Disable VCS-based implicit rules.
% : SCCS/s.%

# Disable VCS-based implicit rules.
% : s.%

.SUFFIXES: .hpux_make_needs_suffix_list

# Command-line flag to silence nested $(MAKE).
$(VERBOSE)MAKESILENT = -s

#Suppress display of executed commands.
$(VERBOSE).SILENT:

# A target that is always out of date.
cmake_force:
.PHONY : cmake_force

#=============================================================================
# Set environment variables for the build.

# The shell in which to execute make rules.
SHELL = /bin/sh

# The CMake executable.
CMAKE_COMMAND = /usr/bin/cmake

# The command to remove a file.
RM = /usr/bin/cmake -E rm -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /mnt/c/git/ChatSystem

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /mnt/c/git/ChatSystem/build

# Include any dependencies generated for this target.
include CMakeFiles/http_server.dir/depend.make
# Include any dependencies generated by the compiler for this target.
include CMakeFiles/http_server.dir/compiler_depend.make

# Include the progress variables for this target.
include CMakeFiles/http_server.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/http_server.dir/flags.make

CMakeFiles/http_server.dir/src/main.cpp.o: CMakeFiles/http_server.dir/flags.make
CMakeFiles/http_server.dir/src/main.cpp.o: ../src/main.cpp
CMakeFiles/http_server.dir/src/main.cpp.o: CMakeFiles/http_server.dir/compiler_depend.ts
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/mnt/c/git/ChatSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/http_server.dir/src/main.cpp.o"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -MD -MT CMakeFiles/http_server.dir/src/main.cpp.o -MF CMakeFiles/http_server.dir/src/main.cpp.o.d -o CMakeFiles/http_server.dir/src/main.cpp.o -c /mnt/c/git/ChatSystem/src/main.cpp

CMakeFiles/http_server.dir/src/main.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/http_server.dir/src/main.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /mnt/c/git/ChatSystem/src/main.cpp > CMakeFiles/http_server.dir/src/main.cpp.i

CMakeFiles/http_server.dir/src/main.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/http_server.dir/src/main.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /mnt/c/git/ChatSystem/src/main.cpp -o CMakeFiles/http_server.dir/src/main.cpp.s

# Object files for target http_server
http_server_OBJECTS = \
"CMakeFiles/http_server.dir/src/main.cpp.o"

# External object files for target http_server
http_server_EXTERNAL_OBJECTS =

http_server: CMakeFiles/http_server.dir/src/main.cpp.o
http_server: CMakeFiles/http_server.dir/build.make
http_server: /usr/lib/x86_64-linux-gnu/libssl.so
http_server: /usr/lib/x86_64-linux-gnu/libcrypto.so
http_server: CMakeFiles/http_server.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/mnt/c/git/ChatSystem/build/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX executable http_server"
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/http_server.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/http_server.dir/build: http_server
.PHONY : CMakeFiles/http_server.dir/build

CMakeFiles/http_server.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/http_server.dir/cmake_clean.cmake
.PHONY : CMakeFiles/http_server.dir/clean

CMakeFiles/http_server.dir/depend:
	cd /mnt/c/git/ChatSystem/build && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /mnt/c/git/ChatSystem /mnt/c/git/ChatSystem /mnt/c/git/ChatSystem/build /mnt/c/git/ChatSystem/build /mnt/c/git/ChatSystem/build/CMakeFiles/http_server.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/http_server.dir/depend

