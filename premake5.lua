local current_dir = _SCRIPT_DIR

function IncludeDetouring()
	local refcount = IncludePackage("detouring")

	local _project = project()

	sysincludedirs({
		current_dir .. "/include",
		current_dir .. "/hde/include",
		current_dir .. "/minhook/include"
	})
	links("detouring")

	filter("system:macosx")
		links("CoreServices.framework")

	if refcount == 1 then
		dofile(current_dir .. "/premake5_create_project.lua")
	end

	project(_project.name)
end
