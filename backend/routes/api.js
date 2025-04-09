const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/auth');
const { PistonClient } = require('piston-client'); // Updated package name

const piston = new PistonClient({ server: 'http://localhost:2000' }); // Adjust server URL as needed

router.post('/run', verifyToken, async (req, res) => {
  const { code, language } = req.body;

  if (!code || !language) {
    return res.status(400).json({ error: 'Code and language are required' });
  }

  try {
    const result = await piston.execute(language, code, { version: '11.2.0' }); // Specify C++ version
    res.json({
      output: result.run.stdout,
      error: result.run.stderr || (result.compile ? result.compile.stderr : '')
    });
  } catch (error) {
    console.error('Error executing code:', error.message, error.stack);
    res.status(500).json({ error: `Error executing code: ${error.message}` });
  }
});

module.exports = router;