BASEDIR=$(dirname "$0")
# java -jar $BASEDIR/../../target/scala-2.12/argus-saf-3.2.1-SNAPSHOT-assembly.jar cg -a BOTTOM_UP $BASEDIR/../../benchmarks/NativeFlowBench localhost 55001 $BASEDIR/../../benchmarks/expected_nativeflow_bench.txt

java -jar $BASEDIR/../../target/scala-2.12/argus-saf-3.2.1-SNAPSHOT-assembly.jar cg -a BOTTOM_UP /home/tiger/My_Work/Argus-SAF/test_apk/app-debug.apk /home/tiger/My_Work/Argus-SAF/test_apk/ 55001 $BASEDIR/../../benchmarks/expected_nativeflow_bench.txt