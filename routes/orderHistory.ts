/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { type Request, type Response, type NextFunction } from 'express'

import { ordersCollection } from '../data/mongodb'
import * as security from '../lib/insecurity'
import { ObjectId } from 'mongodb'

export function orderHistory () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const loggedInUser = security.authenticatedUsers.get(req.headers?.authorization?.replace('Bearer ', ''))
    if (loggedInUser?.data?.email && loggedInUser.data.id) {
      const email = loggedInUser.data.email
      const updatedEmail = email.replace(/[aeiou]/gi, '*')
      const order = await ordersCollection.find({ email: updatedEmail })
      res.status(200).json({ status: 'success', data: order })
    } else {
      next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
    }
  }
}

export function allOrders () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const order = await ordersCollection.find()
    res.status(200).json({ status: 'success', data: order.reverse() })
  }
}

export function toggleDeliveryStatus () {
  return async (req: Request, res: Response, next: NextFunction) => {
    const deliveryStatus = !req.body.deliveryStatus
    const eta = deliveryStatus ? '0' : '1'
    // Modified by Rezilant AI, 2026-08-19 17:10:30 GMT, Added validation and sanitization for MongoDB ObjectId to prevent NoSQL injection
    try {
      // Validate that the ID is a valid MongoDB ObjectId
      if (!ObjectId.isValid(req.params.id)) {
        return res.status(400).json({ error: 'Invalid order ID format' })
      }
      
      // Convert string to ObjectId - this ensures type safety
      const orderId = new ObjectId(req.params.id)
      
      // Now use the validated ObjectId in your query
      await ordersCollection.update(
        { _id: orderId }, 
        { $set: { delivered: deliveryStatus, eta } }
      )
      
    } catch (error) {
      return res.status(400).json({ error: 'Invalid order ID' })
    }
    // Original Code
    // await ordersCollection.update({ _id: req.params.id }, { $set: { delivered: deliveryStatus, eta } })
    res.status(200).json({ status: 'success' })
  }
}