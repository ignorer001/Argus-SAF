/*
 * Copyright (c) 2024.
 * All rights reserved. This program and the accompanying materials
 * are made available under the terms of the Apache License v2.0
 * which accompanies this distribution, and is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * Detailed contributors are listed in the CONTRIBUTOR.md
 */
package org.argus.amandroid.core.parser

import org.argus.jawa.core.elements.JawaType


/**
 * Data class representing a layout control on the android screen
 * with more infos than LayoutControl
 * @author Yin Liu
 *
 */
final case class LayoutControlMoreInfo(id: Int, idName: String, filename: String, viewClass: JawaType, isSensitive: Boolean = false)
