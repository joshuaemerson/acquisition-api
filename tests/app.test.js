import request from 'supertest';
import app from '#src/app.js';

describe('API Endpoints', () => {
  describe('GET /health', () => {
    it('should return health status', async () => {
      const res = await request(app).get('/health').expect(200);
      expect(res.body).toHaveProperty('status', 'OK');
      expect(res.body).toHaveProperty('timestamp');
      expect(res.body).toHaveProperty('uptime');
    });
  });

  describe('GET /api', () => {
    it('should return health status', async () => {
      const res = await request(app).get('/api').expect(200);
      expect(res.body).toHaveProperty(
        'message',
        'acquisitions-api is up and running \u{1F680}'
      );
    });
  });

  describe('GET /doesnotexist', () => {
    it('should return 404 for routes that do not exist', async () => {
      const res = await request(app).get('/doesnotexist').expect(404);
      expect(res.body).toHaveProperty('error', 'Route not found');
    });
  });
});
