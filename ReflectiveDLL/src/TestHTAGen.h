#pragma once
#include "includes.h"
#include "Jinja2CppLight.h"
#include "stringhelper.h"
/*
https://stackoverflow.com/questions/34289961/calling-a-javascript-function-from-c
<HTML>
<HEAD>
</HEAD>
<BODY>
<script language="javascript" >
var xml = new ActiveXObject("Microsoft.XMLDOM");
xml.async = false;
var xsl = xml;
xsl.load("KSC_32.xsl");
document.write(xsl.parseError.reason);
xml.transformNode(xsl);
self.close();
</script>
</body>
</html>
*/

namespace TestHTAGen {
	std::string renderFile(std::string javascript, std::map<std::string, std::string> javascript_variables);
}