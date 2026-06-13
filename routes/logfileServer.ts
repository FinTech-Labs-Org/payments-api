/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'
import fs from 'node:fs'

export function serveLogFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-06-13 18:33:54 GMT, Added path traversal protection with normalization and boundary validation
    const LOGS_DIR = path.resolve('logs/')
    const requestedFile = path.normalize(file).replace(/^(\.\.[\/\\])+/, '')
    const fullPath = path.resolve(LOGS_DIR, requestedFile)
    
    if (!fullPath.startsWith(LOGS_DIR)) {
      res.status(400)
      return next(new Error('Invalid file path'))
    }
    
    if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
      res.status(404)
      return next(new Error('File not found'))
    }
    
    res.sendFile(fullPath)

    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('logs/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}