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


object CGGen {
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

    println("appName="+ appName)
    println("certificate=", certificate)
    println("uses_permissions=", uses_permissions)
    println("component_infos=", component_infos)
    println("intent_filter=", intent_filter)
    println("environment_map=", environment_map)
    println("comps=", comps)
    println("layout_ctrl=", layout_ctrl)
    println("layout_ctrl_more=", layout_ctrl_more)


    apk.model.getComponents foreach { comp =>
              println("comp == " + comp)
              val clazz = apk.getClassOrResolve(comp)
              val spark = new InterProceduralSuperSpark(apk)
              val idfg = spark.build(clazz.getDeclaredMethods.map(_.getSignature))
              val icfg = idfg.icfg
              val call_graph = icfg.getCallGraph
              println("call_graph =", call_graph)
              call_graph.getCallMap.foreach{
                case (src, dsts) =>
                  println("src == " + src)
                  println("dsts == " + dsts)
              }
            }
  }
}
