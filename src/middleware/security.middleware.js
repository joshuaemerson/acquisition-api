import aj from '#config/arcjet.js';
import { slidingWindow } from '@arcjet/node';
import logger from '#config/logger.js';

const securityMiddleware = async (req, res, next) => {
  try {
    const role = req.user?.role || 'guest'; // req.user gets attached by the jwt when the user is validated

    let limit;

    if (role === 'admin') {
      limit = 20;
    }
    if (role === 'user') {
      limit = 10;
    }
    if (role === 'guest') {
      limit = 5;
    }

    const client = aj.withRule(
      slidingWindow({
        mode: 'LIVE',
        interval: '1m',
        max: limit,
        name: `${role}-rate-limit`,
      })
    );
    const decision = await client.protect(req); // make a decision on whether this request will be allowed based on the rules defined (any rule fails request is denied)

    if (decision.isDenied() && decision.reason.isBot()) {
      logger.warn('Bot request was blocked', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
      });
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Automated requests are not permitted',
      });
    }

    // Based on the 10 most common types of attacks
    if (decision.isDenied() && decision.reason.isShield()) {
      logger.warn('Blocked request according to Shield', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
        method: req.method,
      });
      return res.status(403).json({
        error: 'Forbidden',
        message: 'Request was non compliant according to security policy',
      });
    }

    if (decision.isDenied() && decision.reason.isRateLimit()) {
      logger.warn('Rate limit exceeded', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        path: req.path,
      });
      return res
        .status(403)
        .json({ error: 'Forbidden', message: 'Too many requests' });
    }

    next(); // pass on control to next middleware
  } catch (e) {
    logger.error('Arcjet middleware error', e);
    res.status(500).json({
      error: 'Internal server error',
      message: 'An issue occured with the security middleware',
    });
  }
};

export default securityMiddleware;
