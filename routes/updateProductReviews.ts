/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import * as challengeUtils from '../lib/challengeUtils'
import { challenges } from '../data/datacache'
import * as security from '../lib/insecurity'
import * as db from '../data/mongodb'
import { ObjectId } from 'mongodb' // Modified by Rezilant AI, 2026-08-19 17:06:12 GMT, Added import for ObjectId to validate MongoDB IDs

// vuln-code-snippet start noSqlReviewsChallenge forgedReviewChallenge
export function updateProductReviews () {
  return (req: Request, res: Response, next: NextFunction) => {
    const user = security.authenticatedUsers.from(req) // vuln-code-snippet vuln-line forgedReviewChallenge
    // Modified by Rezilant AI, 2026-08-19 17:06:12 GMT, Added validation to prevent NoSQL injection by validating ID format
    // Validate that the id is a valid ObjectId string
    if (!req.body.id || typeof req.body.id !== 'string') {
      return res.status(400).json({ error: 'Invalid ID format' });
    }

    let validatedId;
    try {
      // Convert to ObjectId to ensure it's properly typed and sanitized
      validatedId = new ObjectId(req.body.id);
    } catch (error) {
      return res.status(400).json({ error: 'Invalid ID format' });
    }

    db.reviewsCollection.update( // vuln-code-snippet neutral-line forgedReviewChallenge
      // Original Code
      // { _id: req.body.id }, // vuln-code-snippet vuln-line noSqlReviewsChallenge forgedReviewChallenge
      { _id: validatedId }, // Modified by Rezilant AI, 2026-08-19 17:06:12 GMT, Use validated ObjectId instead of raw req.body.id
      { $set: { message: req.body.message } },
      { multi: true } // vuln-code-snippet vuln-line noSqlReviewsChallenge
    ).then(
      (result: { modified: number, original: Array<{ author: any }> }) => {
        challengeUtils.solveIf(challenges.noSqlReviewsChallenge, () => { return result.modified > 1 }) // vuln-code-snippet hide-line
        challengeUtils.solveIf(challenges.forgedReviewChallenge, () => { return user?.data && result.original[0] && result.original[0].author !== user.data.email && result.modified === 1 }) // vuln-code-snippet hide-line
        res.json(result)
      }, (err: unknown) => {
        res.status(500).json(err)
      })
  }
}
// vuln-code-snippet end noSqlReviewsChallenge forgedReviewChallenge