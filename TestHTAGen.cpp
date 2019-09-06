#include "TestHTAGen.h"

std::string TestHTAGen::renderFile(std::string javascript, std::map<std::string, std::string> javascript_variables)
{
	Jinja2CppLight::Template hta(R"d(
<HTML>
<HEAD>
</HEAD>
<BODY>
<script language="javascript" >
{{javascript}}
</script>
</body>
</html>
	)d");
	Jinja2CppLight::Template javascript_tpl(javascript);
	// for every variable the javascript needs to render
	for (auto const& it : javascript_variables) {
		try
		{
			javascript_tpl.setValue(it.first, it.second);
		}
		catch (const std::exception&)
		{
			// fail silently?
#ifdef DEBUG
			std::cout << "error rendering variable '" << it.first << "'" << std::endl;
#endif // DEBUG

			
		}
	}
	hta.setValue("javascript", javascript_tpl.render());
	return hta.render();
}
// https://stackoverflow.com/questions/34289961/calling-a-javascript-function-from-c