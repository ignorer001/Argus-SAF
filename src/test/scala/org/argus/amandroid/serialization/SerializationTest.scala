/*
 * Copyright (c) 2017. Fengguo Wei and others.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Eclipse Public License v1.0
 * which accompanies this distribution, and is available at
 * http://www.eclipse.org/legal/epl-v10.html
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */

package org.argus.amandroid.serialization

import java.io.{FileReader, FileWriter}

import org.argus.amandroid.alir.componentSummary.ApkYard
import org.argus.amandroid.core.decompile.{ConverterUtil, DecompileLayout, DecompilerSettings}
import org.argus.amandroid.core.model.ApkModel
import org.argus.jawa.core.DefaultReporter
import org.argus.jawa.core.util.MyFileUtil
import org.json4s.NoTypeHints
import org.json4s.native.Serialization
import org.json4s.native.Serialization.{read, write}
import org.scalatest.{FlatSpec, Matchers}
import org.sireum.util.FileUtil

/**
  * Created by fgwei on 3/23/17.
  */
class SerializationTest extends FlatSpec with Matchers {

  "ApkModel" should "successfully serialized and deserialized" in {
    val apkFile = getClass.getResource("/icc-bench/IccHandling/icc_explicit_src_sink.apk").getPath
    val apkUri = FileUtil.toUri(apkFile)
    val outputUri = FileUtil.toUri(apkFile.substring(0, apkFile.length - 4))
    val yard = new ApkYard(new DefaultReporter)
    val layout = DecompileLayout(outputUri)
    val settings = DecompilerSettings(None, dexLog = false, debugMode = false, removeSupportGen = true, forceDelete = true, None, layout)
    val apk = yard.loadApk(apkUri, settings)
    val model = apk.model
    implicit val formats = Serialization.formats(NoTypeHints) + ApkModelSerializer
    val apkRes = FileUtil.toFile(MyFileUtil.appendFileName(outputUri, "apk.json"))
    val oapk = new FileWriter(apkRes)
    try {
      write(model, oapk)
    } catch {
      case e: Exception =>
        e.printStackTrace()
    } finally {
      oapk.flush()
      oapk.close()
    }
    val iapk = new FileReader(apkRes)
    var newApkModel: ApkModel = null
    try {
      newApkModel = read[ApkModel](iapk)
    } catch {
      case e: Exception =>
        e.printStackTrace()
    } finally {
      iapk.close()
      ConverterUtil.cleanDir(outputUri)
    }
    require(
      model.getAppName == newApkModel.getAppName &&
      model.getComponents == newApkModel.getComponents &&
      model.getLayoutControls == newApkModel.getLayoutControls &&
      model.getCallbackMethods == newApkModel.getCallbackMethods &&
      model.getComponentInfos == newApkModel.getComponentInfos &&
      model.getEnvMap == newApkModel.getEnvMap)
  }
}
