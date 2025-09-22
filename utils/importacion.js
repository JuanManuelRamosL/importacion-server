// ---- Constantes editables ----
const DER_IMPORT_PCT = 0.16; // 16%
const TASA_ESTAD_PCT = 0.03; // 3%
const IVA_PCT = 0.21; // 21%
const SEGURO_PCT = 0.01; // 1%
const HONORARIOS = 60; // USD

const r2 = (x) => Math.round((x + Number.EPSILON) * 100) / 100;

/**
 * Solo requiere producto y flete.
 * El resto usa los valores por defecto de arriba.
 */
function calcularImportacionCourierSimple(producto, flete) {
  const P = Number(producto);
  const F = Number(flete);
  if (!Number.isFinite(P) || !Number.isFinite(F) || P < 0 || F < 0) {
    throw new Error("Producto y flete deben ser números >= 0");
  }

  // 1) Seguro = 1% de (producto + flete)
  const seguro = r2((P + F) * SEGURO_PCT);

  // 2) CIF = producto + flete + seguro
  const cif = r2(P + F + seguro);

  // 3) DE y TE sobre CIF
  const derechosImportacion = r2(cif * DER_IMPORT_PCT);
  const tasaEstadistica = r2(cif * TASA_ESTAD_PCT);

  // 4) Base IVA = CIF + DE + TE; IVA = 21% de Base IVA
  const baseIVA = r2(cif + derechosImportacion + tasaEstadistica);
  const iva = r2(baseIVA * IVA_PCT);

  // 5) Total impuestos y total con courier
  const totalImpuestos = r2(derechosImportacion + tasaEstadistica + iva);
  const totalConCourier = r2(totalImpuestos + HONORARIOS);

  // Costo final total = producto + flete + importación
  const costoFinal = r2(P + F + totalConCourier);

  return {
    seguro,
    cif,
    derechosImportacion,
    tasaEstadistica,
    baseIVA,
    iva,
    totalImpuestos,
    honorariosCourier: HONORARIOS,
    totalConCourier,
    costoFinal,
  };
}

module.exports = { calcularImportacionCourierSimple };
