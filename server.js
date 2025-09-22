const express = require("express");
const { calcularImportacionCourierSimple } = require("./utils/importacion.js");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware para parsear JSON
app.use(express.json());

// Endpoint para calcular importación
app.post("/calcular-importacion", (req, res) => {
  try {
    const { producto, flete } = req.body;

    // Validar que se enviaron los parámetros requeridos
    if (producto === undefined || flete === undefined) {
      return res.status(400).json({
        error: 'Se requieren los parámetros "producto" y "flete"',
      });
    }

    // Calcular importación
    const resultado = calcularImportacionCourierSimple(producto, flete);

    res.json({
      success: true,
      data: resultado,
    });
  } catch (error) {
    res.status(400).json({
      success: false,
      error: error.message,
    });
  }
});

// Endpoint de prueba
app.get("/health", (req, res) => {
  res.json({ status: "OK", message: "Servidor funcionando correctamente" });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`Servidor corriendo en puerto ${PORT}`);
  console.log(
    `Endpoint disponible: POST http://localhost:${PORT}/calcular-importacion`
  );
});
