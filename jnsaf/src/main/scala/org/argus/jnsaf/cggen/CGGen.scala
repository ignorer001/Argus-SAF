package org.argus.jnsaf.cggen

import java.io.File

import org.argus.amandroid.plugin.TaintAnalysisApproach
import org.argus.jawa.core.io.{MsgLevel, PrintReporter}
import org.argus.jawa.core.util._
import org.argus.jawa.flow.taint_result.TaintResult
import org.argus.jnsaf.client.JNSafClient

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{DecompileLayout, DecompileStrategy, DecompilerSettings}
import org.argus.jawa.core.io.DefaultReporter
import org.argus.jawa.core.util.FileUtil


import org.argus.jawa.flow.pta.suspark.InterProceduralSuperSpark

import org.argus.amandroid.core.appInfo.AppInfoCollector
import org.argus.amandroid.core.util.ApkFileUtil
import org.argus.amandroid.core.{AndroidGlobalConfig, ApkGlobal}
import org.argus.jawa.flow.Context


import org.argus.jawa.core.JawaMethod
import org.argus.jawa.flow.JawaAlirInfoProvider

import org.argus.jawa.flow.cfg.{ICFGCallNode, ICFGExitNode, ICFGNormalNode}


object CGGen {
  val LOG_ENABLE = false
  def apply(apkPath: String, outputPath: String, port: Int, approach: TaintAnalysisApproach.Value): Unit = {
    println("in CGGen's apply")
    println("usage: apk_path output_path")
    val apk_path = apkPath
    val output_path = outputPath
    val fileUri = FileUtil.toUri(apk_path)
    val outputUri = FileUtil.toUri(output_path)
    val reporter = new DefaultReporter
    // Yard is the apks manager
    val yard = new ApkYard(reporter)
    val layout = DecompileLayout(outputUri)
    val strategy = DecompileStrategy(layout)
    val settings = DecompilerSettings(debugMode = false, forceDelete = true, strategy, reporter)
    // apk is the apk meta data manager, class loader and class manager
    val apk = yard.loadApk(fileUri, settings, collectInfo = true, resolveCallBack = true)

    val appName = apk.model.getAppName
    val certificate = apk.model.getCertificates
    val uses_permissions = apk.model.getUsesPermissions
    val component_infos = apk.model.getComponentInfos // ComponentInfo(compType: [class type], typ: [ACTIVITY, SERVICE, RECEIVER, PROVIDER], exported: Boolean, enabled: Boolean, permission: ISet[String])
    val intent_filter = apk.model.getIntentFilterDB // IntentFilterDB contains intent filter information for each component.
    val environment_map = apk.model.getEnvMap // environment method map
    val layout_ctrl = apk.model.getLayoutControls
    val layout_ctrl_more = apk.model.getLayoutControlsMoreInfo
    val comps = apk.model.getComponents
    
    val callbackmap = apk.model.getCallbackMethodMapping
    val callbacks = apk.model.getCallbackMethods
    val envstring = apk.model.getEnvString
    val rpcmethod_map = apk.model.getRpcMethodMapping
    val rpcmethod = apk.model.getRpcMethods
    val codeline = apk.model.getCodeLineCounter
    val intentfilter_DB = apk.model.getIntentFilterDB

    if (LOG_ENABLE == true) {
        println("appName="+ appName)
        println("certificate=", certificate)
        println("uses_permissions=", uses_permissions)
        println("component_infos=", component_infos)
        println("intent_filter=", intent_filter)
        println("environment_map=", environment_map)
        println("comps=", comps)
        println("layout_ctrl=", layout_ctrl)
        println("layout_ctrl_more=", layout_ctrl_more)

        println("callbackmap="+ callbackmap)
        println("callbacks=", callbacks)
        println("envstring=", envstring)
        println("rpcmethod_map=", rpcmethod_map)
        println("rpcmethod=", rpcmethod)
        println("codeline=", codeline)
        println("intentfilter_DB=", intentfilter_DB)
    }

    apk.model.getComponents foreach { comp =>
              println("comp == " + comp)
              println("Iam in ---------------------------------------------apk.model.getComponents foreach")
              val clazz = apk.getClassOrResolve(comp)
              println("clazz == " + clazz)
              // should we use AndroidReachingFactsAnalysis to get the graphs?
              // see here: http://pag.arguslab.org/argus-saf#tutorial-graph-idfg
              val spark = new InterProceduralSuperSpark(apk)
              println("spark == " + spark)
              println("clazz.getDeclaredMethods == " + clazz.getDeclaredMethods)
              println("clazz.getDeclaredMethods.map(_.getSignature) == " + clazz.getDeclaredMethods.map(_.getSignature))
              println("before idfg-----------------")
              val idfg = spark.build(clazz.getDeclaredMethods.map(_.getSignature))
              println("after idfg-----------------")
              // println("idfg == " + idfg)
              println("before icfg-----------------")
              val icfg = idfg.icfg
              println("after icfg-----------------")
              // println("icfg == " + icfg)


              // walk through icfg
              val sb = new StringBuilder("CFG\n")
              for (n <- icfg.nodes)
                  for (m <- icfg.successors(n)) {
                      for (_ <- icfg.getEdges(n, m)) {
                          println(s"${n.toString} -> ${m.toString}\n")
                          // sb.append(s"${n.toString} -> ${m.toString}\n")
                      }
                  }
              // println(sb)

              // https://github.com/arguslab/Argus-SAF/blob/06596c6bb03fe2560030b52bf2b47d17d1bd3068/jawa/src/main/scala/org/argus/jawa/flow/dda/InterProceduralDataDependenceAnalysis.scala#L75
              icfg.nodes.foreach {
                case cn: ICFGCallNode =>
                  println("Iam call node == " + cn.toString)
                case en: ICFGExitNode =>
                  println("Iam ICFGExitNode node == " + en.toString)
                case _ =>
              }
              // next step, check the usage of "isCall"


              println("before call_graph-----------------")
              val call_graph = icfg.getCallGraph
              println("after call_graph-----------------")
              // when we generate the graph, can we check findViewById and setContentView these kind of View related function
              // also, can we check the idName, such as btn_java2c
              // findings:
              // 1. we can find mylayout in both idfg and icfg
              // 2. we can find btn_java2c in both idfg and icfg
              // 3. we can find lots of findViewById and setContentView in both idfg and icfg
              println("call_graph =", call_graph)
              call_graph.getCallMap.foreach{
                case (src, dsts) =>
                  println("src == " + src)
                  println("dsts == " + dsts)
              }
            }
  }
}
