group("garrysmod_common")
	project("detouring")
		kind("StaticLib")
		location("projects/" .. os.target() .. "/" .. _ACTION)
		targetdir("%{prj.location}/%{cfg.architecture}/%{cfg.buildcfg}")
		debugdir("%{prj.location}/%{cfg.architecture}/%{cfg.buildcfg}")
		objdir("!%{prj.location}/%{cfg.architecture}/%{cfg.buildcfg}/intermediate/%{prj.name}")
		includedirs({"include/detouring", "hde/include", "minhook/include"})
		files({
			"include/detouring/*.hpp",
			"include/detouring/*.h",
			"source/*.cpp",
			"hde/include/*.h",
			"hde/src/hde.c",
			"minhook/include/*.h",
			"minhook/src/*.h",
			"minhook/src/*.c"
		})
		vpaths({
			["Header files"] = {
				"include/detouring/*.hpp",
				"include/detouring/*.h"
			},
			["Header files/hde"] = "hde/include/*.h",
			["Header files/minhook"] = {
				"minhook/include/*.h",
				"minhook/src/*.h"
			},
			["Source files"] = "source/*.cpp",
			["Source files/hde"] = "hde/src/*.c",
			["Source files/minhook"] = "minhook/src/*.c"
		})

		filter("files:**.c")
			language("C")
