# CMAKE generated file: DO NOT EDIT!
# Generated by "Unix Makefiles" Generator, CMake Version 3.16

# Delete rule output on recipe failure.
.DELETE_ON_ERROR:


#=============================================================================
# Special targets provided by cmake.

# Disable implicit rules so canonical targets will work.
.SUFFIXES:


# Remove some rules from gmake that .SUFFIXES does not remove.
SUFFIXES =

.SUFFIXES: .hpux_make_needs_suffix_list


# Suppress display of executed commands.
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
RM = /usr/bin/cmake -E remove -f

# Escaping for special characters.
EQUALS = =

# The top-level source directory on which CMake was run.
CMAKE_SOURCE_DIR = /usr0/home/ahp2/Documents/coded_pir/src/c

# The top-level build directory on which CMake was run.
CMAKE_BINARY_DIR = /usr0/home/ahp2/Documents/coded_pir/src/c

# Include any dependencies generated for this target.
include CMakeFiles/Client.dir/depend.make

# Include the progress variables for this target.
include CMakeFiles/Client.dir/progress.make

# Include the compile flags for this target's objects.
include CMakeFiles/Client.dir/flags.make

CMakeFiles/Client.dir/client.cpp.o: CMakeFiles/Client.dir/flags.make
CMakeFiles/Client.dir/client.cpp.o: client.cpp
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --progress-dir=/usr0/home/ahp2/Documents/coded_pir/src/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_1) "Building CXX object CMakeFiles/Client.dir/client.cpp.o"
	/usr/bin/c++  $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -o CMakeFiles/Client.dir/client.cpp.o -c /usr0/home/ahp2/Documents/coded_pir/src/c/client.cpp

CMakeFiles/Client.dir/client.cpp.i: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Preprocessing CXX source to CMakeFiles/Client.dir/client.cpp.i"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -E /usr0/home/ahp2/Documents/coded_pir/src/c/client.cpp > CMakeFiles/Client.dir/client.cpp.i

CMakeFiles/Client.dir/client.cpp.s: cmake_force
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green "Compiling CXX source to assembly CMakeFiles/Client.dir/client.cpp.s"
	/usr/bin/c++ $(CXX_DEFINES) $(CXX_INCLUDES) $(CXX_FLAGS) -S /usr0/home/ahp2/Documents/coded_pir/src/c/client.cpp -o CMakeFiles/Client.dir/client.cpp.s

# Object files for target Client
Client_OBJECTS = \
"CMakeFiles/Client.dir/client.cpp.o"

# External object files for target Client
Client_EXTERNAL_OBJECTS =

libClient.a: CMakeFiles/Client.dir/client.cpp.o
libClient.a: CMakeFiles/Client.dir/build.make
libClient.a: CMakeFiles/Client.dir/link.txt
	@$(CMAKE_COMMAND) -E cmake_echo_color --switch=$(COLOR) --green --bold --progress-dir=/usr0/home/ahp2/Documents/coded_pir/src/c/CMakeFiles --progress-num=$(CMAKE_PROGRESS_2) "Linking CXX static library libClient.a"
	$(CMAKE_COMMAND) -P CMakeFiles/Client.dir/cmake_clean_target.cmake
	$(CMAKE_COMMAND) -E cmake_link_script CMakeFiles/Client.dir/link.txt --verbose=$(VERBOSE)

# Rule to build all files generated by this target.
CMakeFiles/Client.dir/build: libClient.a

.PHONY : CMakeFiles/Client.dir/build

CMakeFiles/Client.dir/clean:
	$(CMAKE_COMMAND) -P CMakeFiles/Client.dir/cmake_clean.cmake
.PHONY : CMakeFiles/Client.dir/clean

CMakeFiles/Client.dir/depend:
	cd /usr0/home/ahp2/Documents/coded_pir/src/c && $(CMAKE_COMMAND) -E cmake_depends "Unix Makefiles" /usr0/home/ahp2/Documents/coded_pir/src/c /usr0/home/ahp2/Documents/coded_pir/src/c /usr0/home/ahp2/Documents/coded_pir/src/c /usr0/home/ahp2/Documents/coded_pir/src/c /usr0/home/ahp2/Documents/coded_pir/src/c/CMakeFiles/Client.dir/DependInfo.cmake --color=$(COLOR)
.PHONY : CMakeFiles/Client.dir/depend

