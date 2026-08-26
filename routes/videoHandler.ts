/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs from 'node:fs'
import config from 'config'
import { type Request, type Response } from 'express'
import { AllHtmlEntities as Entities } from 'html-entities'

import * as challengeUtils from '../lib/challengeUtils'
import { themes } from '../views/themes/themes'
import { challenges } from '../data/datacache'
import * as utils from '../lib/utils'

const entities = new Entities()

export const getVideo = () => {
  return (req: Request, res: Response) => {
    const path = videoPath()
    const stat = fs.statSync(path)
    const fileSize = stat.size
    const range = req.headers.range
    if (range) {
      const parts = range.replace(/bytes=/, '').split('-')
      const start = parseInt(parts[0], 10)
      const end = parts[1] ? parseInt(parts[1], 10) : fileSize - 1
      const chunksize = (end - start) + 1
      const file = fs.createReadStream(path, { start, end })
      const head = {
        'Content-Range': `bytes ${start}-${end}/${fileSize}`,
        'Accept-Ranges': 'bytes',
        'Content-Length': chunksize,
        'Content-Location': '/assets/public/videos/owasp_promo.mp4',
        'Content-Type': 'video/mp4'
      }
      res.writeHead(206, head)
      file.pipe(res)
    } else {
      const head = {
        'Content-Length': fileSize,
        'Content-Type': 'video/mp4'
      }
      res.writeHead(200, head)
      fs.createReadStream(path).pipe(res)
    }
  }
}

export const promotionVideo = () => {
  return (req: Request, res: Response) => {
    fs.readFile('views/promotionVideo.pug', async function (err, buf) {
      if (err != null) throw err
      let template = buf.toString()
      const subs = getSubsFromFile()

      challengeUtils.solveIf(challenges.videoXssChallenge, () => { return utils.contains(subs, '&lt;/script>&lt;script>alert(`xss`)&lt;/script>') })

      const themeKey = config.get&lt;string>('application.theme') as keyof typeof themes
      const theme = themes[themeKey] || themes['bluegrey-lightgreen']
      template = template.replace(/_title_/g, entities.encode(config.get&lt;string>('application.name')))
      template = template.replace(/_favicon_/g, favicon())
      template = template.replace(/_bgColor_/g, theme.bgColor)
      template = template.replace(/_textColor_/g, theme.textColor)
      template = template.replace(/_navColor_/g, theme.navColor)
      template = template.replace(/_primLight_/g, theme.primLight)
      template = template.replace(/_primDark_/g, theme.primDark)
      const pug = (await import('pug')).default
      const fn = pug.compile(template)
      let compiledTemplate = fn()
      // Modified by Rezilant AI, 2026-08-26 17:38:03 GMT, Sanitize subtitle data to prevent XSS injection
      const sanitizeSubs = (input: string): string => {
        return input
          .replace(/&/g, '&')
          .replace(/&lt;/g, '&lt;')
          .replace(/>/g, '>')
          .replace(/"/g, '"')
          .replace(/'/g, ''');
      }
      compiledTemplate = compiledTemplate.replace('&lt;script id="subtitle">&lt;/script>', '&lt;script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + sanitizeSubs(subs) + '&lt;/script>')
      // Original Code
      // compiledTemplate = compiledTemplate.replace('&lt;script id="subtitle">&lt;/script>', '&lt;script id="subtitle" type="text/vtt" data-label="English" data-lang="en">' + subs + '&lt;/script>')
      res.send(compiledTemplate)
    })
  }
  function favicon () {
    return utils.extractFilename(config.get('application.favicon'))
  }
}

function getSubsFromFile () {
  const subtitles = config.get&lt;string>('application.promotion.subtitles') ?? 'owasp_promo.vtt'
  const data = fs.readFileSync('frontend/dist/frontend/assets/public/videos/' + subtitles, 'utf8')
  return data.toString()
}

function videoPath () {
  if (config.get&lt;string>('application.promotion.video') !== null) {
    const video = utils.extractFilename(config.get&lt;string>('application.promotion.video'))
    return 'frontend/dist/frontend/assets/public/videos/' + video
  }
  return 'frontend/dist/frontend/assets/public/videos/owasp_promo.mp4'
}