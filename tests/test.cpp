#include <string>
#include <cppunit/extensions/TestFactoryRegistry.h>
#include <cppunit/ui/text/TestRunner.h>
#include <locale.h>

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "");

	CppUnit::TextUi::TestRunner runner;
	CppUnit::TestFactoryRegistry &registry = CppUnit::TestFactoryRegistry::getRegistry();
	runner.addTest(registry.makeTest());
	bool wasSuccessful = runner.run((argc > 1) ? argv[1] : "", false);

	return wasSuccessful ? 0 : 1;
}
