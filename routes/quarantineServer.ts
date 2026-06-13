/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import fs from 'node:fs'
import { type Request, type Response, type NextFunction } from 'express'

export function serveQuarantineFiles () {
  return ({ params, query }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // Modified by Rezilant AI, 2026-06-13 18:33:52 GMT, Added path sanitization and validation to prevent directory traversal attacks
    // Define the allowed directory
    const QUARANTINE_DIR = path.resolve('ftp/quarantine/')
    
    // Validate and sanitize the file input - Remove any directory traversal sequences
    const sanitizedFile = path.basename(file)
    const fullPath = path.resolve(QUARANTINE_DIR, sanitizedFile)
    
    // Verify the resolved path is still within the quarantine directory
    if (!fullPath.startsWith(QUARANTINE_DIR + path.sep)) {
      res.status(403)
      return next(new Error('Access denied'))
    }
    
    // Additional validation: check if file exists and is a file (not directory)
    if (!fs.existsSync(fullPath) || !fs.statSync(fullPath).isFile()) {
      res.status(404)
      return next(new Error('File not found'))
    }
    
    res.sendFile(fullPath)
    
    // Original Code
    // if (!file.includes('/')) {
    //   res.sendFile(path.resolve('ftp/quarantine/', file))
    // } else {
    //   res.status(403)
    //   next(new Error('File names cannot contain forward slashes!'))
    // }
  }
}