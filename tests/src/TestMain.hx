import utest.Runner;
import utest.ui.Report;

class TestMain {
	public static function main():Void {
		var runner:Runner = new Runner();
		runner.addCase(new wsproto.FrameTest());
		runner.addCase(new wsproto.HandshakeTest());
		runner.addCase(new wsproto.TextTest());
		runner.addCase(new wsproto.SessionTest());
		runner.addCase(new wsproto.FuzzTest());
		#if (cpp || hl || neko)
		runner.addCase(new wsproto.SocketTest());
		#end
		#if sys
		// Each test is named as it starts, so a run that hangs shows where
		runner.onTestStart.add(function(handler) {
			Sys.println("Running " + Type.getClassName(Type.getClass(handler.fixture.target)) + "." + handler.fixture.method);
			Sys.stdout().flush();
		});
		#end
		Report.create(runner);
		runner.run();
	}
}
