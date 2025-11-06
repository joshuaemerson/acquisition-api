// Set up express application with the correct middleware
import express from 'express';

const app = express();

app.get('/', (req, res) => {
  res.status(200).send('Hello From the Acquisitions API');
});

export default app;
