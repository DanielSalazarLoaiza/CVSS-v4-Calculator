<?php
namespace App\Http\Controllers;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\File;


# Clase representativa de un vector CVSS(Common Vulnerability Scoring System) v4.0 vector
# En matemáticas e informática, un vector es un conjunto de elementos (generalmente números) que puede
# representar diferentes dimensiones de datos. De forma similar, en CVSS, la cadena vectorial representa varias
# dimensiones de las características de una vulnerabilidad.
# Esta clase enpasula las métricas CVSS 4.0 lo que permite la creación, manipulación y validación de vectores CVSS.
# Permite generar una cadena vectorial dinámicamente en función de los valores actuales de las métricas, actualizar
# las métricas a partir de una cadena vectorial de entrada, y calcular clases equivalentes para evaluaciones de 
# nivel superior. 
class Cvss4Controller extends Controller
{
    # EJEMPLO: 
    # roundTDecimalPlaces(4.945833333333333); -- Retornara 4.9
    # roundToDecimalPlaces(4.25); -- Retornara 4.3
    # RoundToDecimalPlaces(1.4499999999999993); -- Retornara 1.5
    public function roundToDecimalPlaces($value)
    {
        $epsilon = pow(10, -6);
        return round(($value + $epsilon) * 10) / 10;
    }

    # Métricas CVSS 4.0 con valores predeterminados en la primera clave
    static array $metrics = [
        # BASE (11 Métricas)
        "BASE" => [
            "AV" => ["N", "A", "L", "P"],
            "AC" => ["L", "H"],
            "AT" => ["N", "P"],
            "PR" => ["N", "L", "H"],
            "UI" => ["N", "P", "A"],
            "VC" => ["N", "L", "H"],
            "VI" => ["N", "L", "H"],
            "VA" => ["N", "L", "H"],
            "SC" => ["N", "L", "H"],
            "SI" => ["N", "L", "H"],
            "SA" => ["N", "L", "H"],
        ],

        # Amenaza (1 Métrica)
        "THREAT" => [
            "E" => ["X", "A", "P", "U"]
        ],

        # Ambiental (14 Métricas)
        "ENVIRONMENTAL" => [
            "CR" => ["X", "H", "M", "L"],
            "IR" => ["X", "H", "M", "L"],
            "AR" => ["X", "H", "M", "L"],
            "MAV" => ["X", "N", "A", "L", "P"],
            "MAC" => ["X", "L", "H"],
            "MAT" => ["X", "N", "P"],
            "MPR" => ["X", "N", "L", "H"],
            "MUI" => ["X", "N", "P", "A"],
            "MVC" => ["X", "H", "L", "N"],
            "MVI" => ["X", "H", "L", "N"],
            "MVA" => ["X", "H", "L", "N"],
            "MSC" => ["X", "H", "L", "N"],
            "MSI" => ["X", "S", "H", "L", "N"],
            "MSA" => ["X", "S", "H", "L", "N"],
        ],

        # Suplementario (6 Métricas)
        "SUPPLEMENTAL" => [
            "S" => ["X", "N", "P"],
            "AU" => ["X", "N", "Y"],
            "R" => ["X", "A", "U", "I"],
            "V" => ["X", "D", "C"],
            "RE" => ["X", "L", "M", "H"],
            "U" => ["X", "Clear", "Green", "Amber", "Red"],
        ],
    ];

    # Array que contendrá todas las métricas combinadas
    public static array $all_metrics = [];

    # Genera $all_metrics combinando todos los valores de cada categoría
    # (Equivalente al reduce + spread {...order, ...category} en JavaScript)
    public static function initAllMetrics()
    {
        # Mezcla todos los arrays internos en uno solo 
        foreach (self::$metrics as $category => $values) {
            self::$all_metrics = array_merge(self::$all_metrics, $values);
        }
    }

    # Constante base de nomenclatura para CVSS 4.0
    const BASE_NOMENCLATURE = "CVSS-B";

    # Inicializa una nueva instancia de Vector con una cadena de vector CVSS opcional.
    # Este constructor inicializa las métricas con sus valores predeterminados según la especificación CVSS 4.0
    # Si se proporciona una cadena de vector, la analiza y actualiza las métricas según corresponda.
    public array $currentMetrics = [];

    public function __construct()
    {
        # Inicializa $all_metrics si no existe
        if (empty(self::$all_metrics)) {
            self::initAllMetrics();
        }

        # Inicializar valores por defecto 
        $selected = [];

        foreach (self::$metrics as $category => $items) {
            foreach ($items as $key => $values) {
                $selected[$key] = $values[0]; # Primer valor == default
            }
        }

        $this->currentMetrics = $selected;
    }

    # genera dinámicamente la cadena vectorial CVSS sin procesar basándose en el estado actual de 'metrics'.
    # Este getter Construye la cadena vectorial a partar del objeto 'metrics', incluyendo solo las métricas 
    # que no están estbalecidas en "X". La cadena comienza con "CVSS:4.0" seguido de esta métrica y su valor. 
    public function getRawVector()
    {
        $base = "CVSS:4.0"; # Base de nomenclatura para CVSS 4.0
        $parts = []; # Array para almacenar las partes de la cadena vectorial

        # Recorrer todas las métricas y agregar las que no están en "X"
        foreach ($this->currentMetrics as $key => $value) {
            # Ignorar métricas con valor "X"
            if ($value !== "X") {
                $parts[] = "{$key}:{$value}";
            }
        }

        return $base . "/" . implode("/", $parts);
    }

    # Calcula las clases equivalentes para las métricas CVSS dadas.
    # Este método agrega múltiples métricas de seguridad detalladas en clases equivalentes
    # de nivel superior que representan la postura de seguridad general
    public function getEquivalentClasses()
    {
        # Función auxiliar para calcular EQ1
        $computeEQ1 = function ()
        {
            $av = $this->getEffectiveMetricValue("AV");
            $pr = $this->getEffectiveMetricValue("PR");
            $ui = $this->getEffectiveMetricValue("UI");

            if ($av === "N" && $pr === "N" && $ui === "N") {
                return "0";
            }
            if (($av === "N" || $pr === "N" || $ui === "N") && !($av === "N" && $pr === "N" && $ui === "N") && $av !== "P") {
                return "1";
            }
            if ($av === "P" || !($av === "N" || $pr === "N" || $ui === "N")) {
                return "2";
            }
        };

        # Función auxiliar para calcular EQ2
        $computeEQ2 = function ()
        {
            $ac = $this->getEffectiveMetricValue("AC");
            $at = $this->getEffectiveMetricValue("AT");

                return ($ac === "L" && $at === "N") ? "0" : "1";
        };

        # Función auxiliar para calcular EQ3
        $computeEQ3 = function ()
        {
            $vc = $this->getEffectiveMetricValue("VC");
            $vi = $this->getEffectiveMetricValue("VI");
            $va = $this->getEffectiveMetricValue("VA");

            if ($vc === "H" && $vi === "H") {
                return "0";
            }
            if (!($vc === "H" && $vi === "H") && ($vc === "H" || $vi === "H" || $va === "H")) {
                return "1";
            }
            if (!($vc === "H" || $vi === "H" || $va === "H")) {
                return "2";
            }
        };

        # Función auxiliar para calcular EQ4
        $computeEQ4 = function ()
        {
            $msi = $this->getEffectiveMetricValue("MSI");
            $msa = $this->getEffectiveMetricValue("MSA");
            $sc = $this->getEffectiveMetricValue("SC");
            $si = $this->getEffectiveMetricValue("SI");
            $sa = $this->getEffectiveMetricValue("SA");

            if ($msi === "S" || $msa === "S") {
                return "0";
            }
            if (!($msi === "S" || $msa === "S") && ($sc === "H" || $si === "H" || $sa === "H")) {
                return "1";
            }
            return "2";
        };

        # Función auxiliar para calcular EQ5
        $computeEQ5 = function ()
        {
            $e = $this->getEffectiveMetricValue("E");

            if ($e === "A") {
                return "0";
            }
            if ($e === "P") {
                return "1";
            }
            if ($e === "U") {
                return "2";
            }
        };

        # Función auxiliar para calcular EQ6
        $computeEQ6 = function ()
        {
            $cr = $this->getEffectiveMetricValue("CR");
            $vc = $this->getEffectiveMetricValue("VC");
            $ir = $this->getEffectiveMetricValue("IR");
            $vi = $this->getEffectiveMetricValue("VI");
            $ar = $this->getEffectiveMetricValue("AR");
            $va = $this->getEffectiveMetricValue("VA");

            if (($cr === "H" && $vc === "H") || ($ir === "H" && $vi === "H") || ($ar === "H" && $va === "H")) {
                return "0";
            }
            return "1";
        };

        # Calcular todos los valores de equivalencia y combinarlos
        return $computeEQ1() . $computeEQ2() . $computeEQ3() . $computeEQ4() . $computeEQ5() . $computeEQ6();
    }

    # Determina la nomenclatura CVSS según las métricas utilizadas en el vector. 
    # Este método genera la cadena de nomenclatura evaluando si el vector incluye
    # métricas de amenazas o ambientales. La nomenclatura ayuda a catgorizar el 
    # tipo de vector(ej: "CVSS-B", "CVSS-BE", "CVSS-BT", "CVSS-BTE")
    public function getNomenclature()
    {
        $nomenclature = self::BASE_NOMENCLATURE;

        $hasThreatMetrics = false;
        foreach (array_keys(self::$metrics['THREAT']) as $metric) {
            if (isset($this->currentMetrics[$metric]) && $this->currentMetrics[$metric] !== 'X') {
                $hasThreatMetrics = true;
                break;
            }
        }

        $hasEnvironmentalMetrics = false;
        foreach (array_keys(self::$metrics['ENVIRONMENTAL']) as $metric) {
            if (isset($this->currentMetrics[$metric]) && $this->currentMetrics[$metric] !== 'X') {
                $hasEnvironmentalMetrics = true;
                break;
            }
        }

        if ($hasThreatMetrics) {
            $nomenclature .= 'T';
        }

        if ($hasEnvironmentalMetrics) {
            $nomenclature .= 'E';
        }

        return $nomenclature;
    }

    # Genera un desglose detallado de las clases equivalentes con sus niveles ed gravedad asociados.
    # Este método analiza una cadena vectorial que representa varias dimensiones de una vulnerabilidad (conocidas
    # como macrovectores) y las asigna a sus correspondientes niveles de gravedad legibles por humnaos. 
    # ("Alta", "Media", "Baja").
    public function getSeverityBreakdown()
    {
        # Obtener los valores equivalentes (ej: "012210")
        $macroVector = $this->getEquivalentClasses();

        # Lista de descripciones en el orden exacto de los dígitos
        $macroVectorDetails = [
            "Exploitability",
            "Complexity",
            "Vulnerable system",
            "Subsequent system",
            "Exploitation",
            "Security requirements"
        ];

        # Macrovectores que tienen solo 2 severidades
        $macroVectorWithTwoSeverities = ["Complexity", "Security requirements"];

        # Tablas de severidad
        $threeSeverities = ["High", "Medium", "Low"];
        $twoSeverities = ["High","Low"];

        # Resultado final
        $breakdown = [];

        foreach ($macroVectorDetails as $index => $description) {
            # Determinar cuál tabla usar
            $options = in_array($description, $macroVectorWithTwoSeverities) ? $twoSeverities : $threeSeverities;

            # Obtener el dígito del macrovector
            $valueIndex = intval($macroVector[$index]);

            # Asignar la severidad
            $breakdown[$description] = $options[$valueIndex] ?? "Unknown";
        }

        return $breakdown;
    }

    # Obtiene el valor efectivo de una métrica CVSS dada. 
    # Este método determina el valor efectivo de una métrica, considerando cualquier modificación y, 
    # por defecto, el peor escenario posible para ciertas métricas.
    # Comprueba si la métrica ha sido anulada por una métrica del entorno y devuelve el valor apropiado.
    public function getEffectiveMetricValue(string $metric)
    {
        # Valores por defecto "worst-case" cuando la métrica está en "X"
        $worstCaseDefaults = [
            "E" => "A",  // Si E = X -> A
            "CR" => "H", // Si CR = X -> H
            "IR" => "H", // Si IR = X -> H
            "AR" => "H", // Si AR = X -> H
        ];

        # Si metric existe y está definido como X en metrics
        if (isset($this->currentMetrics[$metric]) && $this->currentMetrics[$metric] === "X" && array_key_exists( $metric, $worstCaseDefaults)) {
            return $worstCaseDefaults[$metric];
        }

        # Revisión de métricas ambientales (prefijo "M" + metric)
        $modifiedMetric = "M" . $metric;

        if (isset($this->currentMetrics[$modifiedMetric]) && $this->currentMetrics[$modifiedMetric] !== "X") {
            return $this->currentMetrics[$modifiedMetric];
        }

        # Valor normla si no aplica nada anterior
        return $this->currentMetrics[$metric] ?? "X"; # Fallback
    }

    # Valida una cadena vectorial CVSS v4.0
    # Este método verifica la estructura de una cadena vectorial CVSS 4.0
    # para garantizar que se ajuste al formato y los valores esperados. 
    # Verifica la presencia del prefijo "CVSS:4.0", las métricas obligatorias
    # y sus valores válidos.
    public function validateStringVector(string $vector)
    {
        # Separara la cadena por '/'
        $metrics = explode('/', $vector);

        # Validar prefijo "CVSS:4.0"
        $prefix = array_shift($metrics);

        if ($prefix !== "CVSS:4.0") {
            error_log("Error: invalid vector, missing CVSS v4.0 prefix from vector: " . $vector);
            return false;
        }

        # Se espera que #all_metrics esté asi: 
        // [
        //   "AV" => ["N","A","L","P"],
        //   "AC" => ["L","H"],
        //   ...
        // ]

        $expectedMetrics = array_values(self::$all_metrics); # Para que sea iterable por indice
        $expectedMetricKeys = array_keys(self::$all_metrics);

        $mandatoryMetricIndex = 0;

        foreach ($metrics as $metricPart) {
            # Estructura: KEY:VALUE
            if (!str_contains($metricPart, ":")) {
                error_log("Error: invalid format for metric: $metricPart");
                return false;
            }

            [$key, $value] = explode(':', $metricPart);

            # Si hay mas métricas de las permitidas
            if (!isset($expectedMetricKeys[$mandatoryMetricIndex])) {
                error_log("Error: Invalid vector, too many metric values");
                return false;
            }

            # Verificar que la clave exista y está en orden correcto
            # Saltar métricas faltantes
            while (isset($expectedMetricKeys[$mandatoryMetricIndex]) && $expectedMetricKeys[$mandatoryMetricIndex] !== $key) {
                # Si falta una métrica obligatoria (primeras 11)
                if ($mandatoryMetricIndex < 11) {
                    error_log("Error: Invalid vector, missing mandatory metrics.");
                    return false;
                }
                $mandatoryMetricIndex++;
            }

            # Validar que el valor sea permitido
            $validValues = $expectedMetrics[$mandatoryMetricIndex];

            if (!in_array($value, $validValues, true)) {
                error_log("Error: Invalid vector, for key $key, value $value is not in [" . implode(",", $validValues) . "]");
                return false;
            }

            $mandatoryMetricIndex++;
        }

        return true;
    }

    # Actualiza el objeto 'metrics' con los valores de una cadena vectorial CVSS v 4.0 proporcionada.
    # Este método analiza una cadena vectorial CVSS v4.0 y actualiza el objeto 'metrics'
    # con los valores de métrica correspondientes. El método valida la cadena vectorial.
    # para garantizar que se ajuste al formato CVSS v4.0 esperado antes de procesarla. 
    # EJEMPLO DE USO: 
    # vector.updateMetricsFromVectorString("CVSS:4.0/(AV:L/AC:L/PR:N/UI:R/...");
    /**
     * Actualiza la matriz `métricas` con valores de una cadena vectorial CVSS v4.0.
     * 
     * @param string $vectorString
     * @throws \Exception
     */
    public function updateMetricsFromVectorString(string $vectorString)
    {
        if (!$vectorString) {
            throw new \Exception("The vector string cannot be null, undefined, or empty.");
        }

        # Validar el vector de cadena CVSS v4.0
        if (!$this->validateStringVector($vectorString)) {
            throw new \Exception("Invalid CVSS v4.0 vector: " . $vectorString);
        }

        # Dividir el vector
        $metrics = explode('/', $vectorString);

        # Eliminar el prefijo "CVSS:4.0"
        array_shift($metrics);

        # Actualizar las métricas
        foreach ($metrics as $metric) {
            [$key, $value] = explode(':', $metric);
            $this->currentMetrics[$key] = $value;
        }
    }

    # Actualiza el valor de una métrica CVSS específica y refresca automáticamente la cadena vectorial 'raw'
    # Este método actualiza el valor de la métrica especificada en el objeto 'metrics'
    # Después de actualizar la métrica, actualiza la cadena 'raw' reemplazando el valor de la métrica
    # correspondiente en la cadena existente sin reconstruir la cadena completa.
    # EJEMPLOS DE USO
    # vector.updateMetric("AV", "L");
    # console.log(vector.raw); // Output: "CVSS:4.0/AV:L/AC:L/..."
    /**
     * Actualiza el valor de una métrica CVSS específica y refresca la cadena vectorial sin procesar
     * 
     * @param string $metric - La abreviatura de la métrica (ej: "AV", "AC")
     * @param string $value - El nuevo valor a asignar
     */
    public function updateMetric(string $metric, string $value)
    {
        if (array_key_exists($metric, $this->currentMetrics)) {
            $this->currentMetrics[$metric] = $value;
        } else {
            throw new \Exception("Metric {$metric} not found.");
        }
    }

    public static array $LOOKUP_TABLE = [
        "000000" => 10,
        "000001" => 9.9,
        "000010" => 9.8,
        "000011" => 9.5,
        "000020" => 9.5,
        "000021" => 9.2,
        "000100" => 10,
        "000101" => 9.6,
        "000110" => 9.3,
        "000111" => 8.7,
        "000120" => 9.1,
        "000121" => 8.1,
        "000200" => 9.3,
        "000201" => 9,
        "000210" => 8.9,
        "000211" => 8,
        "000220" => 8.1,
        "000221" => 6.8,
        "001000" => 9.8,
        "001001" => 9.5,
        "001010" => 9.5,
        "001011" => 9.2,
        "001020" => 9,
        "001021" => 8.4,
        "001100" => 9.3,
        "001101" => 9.2,
        "001110" => 8.9,
        "001111" => 8.1,
        "001120" => 8.1,
        "001121" => 6.5,
        "001200" => 8.8,
        "001201" => 8,
        "001210" => 7.8,
        "001211" => 7,
        "001220" => 6.9,
        "001221" => 4.8,
        "002001" => 9.2,
        "002011" => 8.2,
        "002021" => 7.2,
        "002101" => 7.9,
        "002111" => 6.9,
        "002121" => 5,
        "002201" => 6.9,
        "002211" => 5.5,
        "002221" => 2.7,
        "010000" => 9.9,
        "010001" => 9.7,
        "010010" => 9.5,
        "010011" => 9.2,
        "010020" => 9.2,
        "010021" => 8.5,
        "010100" => 9.5,
        "010101" => 9.1,
        "010110" => 9,
        "010111" => 8.3,
        "010120" => 8.4,
        "010121" => 7.1,
        "010200" => 9.2,
        "010201" => 8.1,
        "010210" => 8.2,
        "010211" => 7.1,
        "010220" => 7.2,
        "010221" => 5.3,
        "011000" => 9.5,
        "011001" => 9.3,
        "011010" => 9.2,
        "011011" => 8.5,
        "011020" => 8.5,
        "011021" => 7.3,
        "011100" => 9.2,
        "011101" => 8.2,
        "011110" => 8,
        "011111" => 7.2,
        "011120" => 7,
        "011121" => 5.9,
        "011200" => 8.4,
        "011201" => 7,
        "011210" => 7.1,
        "011211" => 5.2,
        "011220" => 5,
        "011221" => 3,
        "012001" => 8.6,
        "012011" => 7.5,
        "012021" => 5.2,
        "012101" => 7.1,
        "012111" => 5.2,
        "012121" => 2.9,
        "012201" => 6.3,
        "012211" => 2.9,
        "012221" => 1.7,
        "100000" => 9.8,
        "100001" => 9.5,
        "100010" => 9.4,
        "100011" => 8.7,
        "100020" => 9.1,
        "100021" => 8.1,
        "100100" => 9.4,
        "100101" => 8.9,
        "100110" => 8.6,
        "100111" => 7.4,
        "100120" => 7.7,
        "100121" => 6.4,
        "100200" => 8.7,
        "100201" => 7.5,
        "100210" => 7.4,
        "100211" => 6.3,
        "100220" => 6.3,
        "100221" => 4.9,
        "101000" => 9.4,
        "101001" => 8.9,
        "101010" => 8.8,
        "101011" => 7.7,
        "101020" => 7.6,
        "101021" => 6.7,
        "101100" => 8.6,
        "101101" => 7.6,
        "101110" => 7.4,
        "101111" => 5.8,
        "101120" => 5.9,
        "101121" => 5,
        "101200" => 7.2,
        "101201" => 5.7,
        "101210" => 5.7,
        "101211" => 5.2,
        "101220" => 5.2,
        "101221" => 2.5,
        "102001" => 8.3,
        "102011" => 7,
        "102021" => 5.4,
        "102101" => 6.5,
        "102111" => 5.8,
        "102121" => 2.6,
        "102201" => 5.3,
        "102211" => 2.1,
        "102221" => 1.3,
        "110000" => 9.5,
        "110001" => 9,
        "110010" => 8.8,
        "110011" => 7.6,
        "110020" => 7.6,
        "110021" => 7,
        "110100" => 9,
        "110101" => 7.7,
        "110110" => 7.5,
        "110111" => 6.2,
        "110120" => 6.1,
        "110121" => 5.3,
        "110200" => 7.7,
        "110201" => 6.6,
        "110210" => 6.8,
        "110211" => 5.9,
        "110220" => 5.2,
        "110221" => 3,
        "111000" => 8.9,
        "111001" => 7.8,
        "111010" => 7.6,
        "111011" => 6.7,
        "111020" => 6.2,
        "111021" => 5.8,
        "111100" => 7.4,
        "111101" => 5.9,
        "111110" => 5.7,
        "111111" => 5.7,
        "111120" => 4.7,
        "111121" => 2.3,
        "111200" => 6.1,
        "111201" => 5.2,
        "111210" => 5.7,
        "111211" => 2.9,
        "111220" => 2.4,
        "111221" => 1.6,
        "112001" => 7.1,
        "112011" => 5.9,
        "112021" => 3,
        "112101" => 5.8,
        "112111" => 2.6,
        "112121" => 1.5,
        "112201" => 2.3,
        "112211" => 1.3,
        "112221" => 0.6,
        "200000" => 9.3,
        "200001" => 8.7,
        "200010" => 8.6,
        "200011" => 7.2,
        "200020" => 7.5,
        "200021" => 5.8,
        "200100" => 8.6,
        "200101" => 7.4,
        "200110" => 7.4,
        "200111" => 6.1,
        "200120" => 5.6,
        "200121" => 3.4,
        "200200" => 7,
        "200201" => 5.4,
        "200210" => 5.2,
        "200211" => 4,
        "200220" => 4,
        "200221" => 2.2,
        "201000" => 8.5,
        "201001" => 7.5,
        "201010" => 7.4,
        "201011" => 5.5,
        "201020" => 6.2,
        "201021" => 5.1,
        "201100" => 7.2,
        "201101" => 5.7,
        "201110" => 5.5,
        "201111" => 4.1,
        "201120" => 4.6,
        "201121" => 1.9,
        "201200" => 5.3,
        "201201" => 3.6,
        "201210" => 3.4,
        "201211" => 1.9,
        "201220" => 1.9,
        "201221" => 0.8,
        "202001" => 6.4,
        "202011" => 5.1,
        "202021" => 2,
        "202101" => 4.7,
        "202111" => 2.1,
        "202121" => 1.1,
        "202201" => 2.4,
        "202211" => 0.9,
        "202221" => 0.4,
        "210000" => 8.8,
        "210001" => 7.5,
        "210010" => 7.3,
        "210011" => 5.3,
        "210020" => 6,
        "210021" => 5,
        "210100" => 7.3,
        "210101" => 5.5,
        "210110" => 5.9,
        "210111" => 4,
        "210120" => 4.1,
        "210121" => 2,
        "210200" => 5.4,
        "210201" => 4.3,
        "210210" => 4.5,
        "210211" => 2.2,
        "210220" => 2,
        "210221" => 1.1,
        "211000" => 7.5,
        "211001" => 5.5,
        "211010" => 5.8,
        "211011" => 4.5,
        "211020" => 4,
        "211021" => 2.1,
        "211100" => 6.1,
        "211101" => 5.1,
        "211110" => 4.8,
        "211111" => 1.8,
        "211120" => 2,
        "211121" => 0.9,
        "211200" => 4.6,
        "211201" => 1.8,
        "211210" => 1.7,
        "211211" => 0.7,
        "211220" => 0.8,
        "211221" => 0.2,
        "212001" => 5.3,
        "212011" => 2.4,
        "212021" => 1.4,
        "212101" => 2.4,
        "212111" => 1.2,
        "212121" => 0.5,
        "212201" => 1,
        "212211" => 0.3,
        "212221" => 0.1,
    ];

    public static array $METRIC_LEVELS = [
        "AV" => ["N" => 0.0, "A" => 0.1, "L" => 0.2, "P" => 0.3],
        "PR" => ["N" => 0.0, "L" => 0.1, "H" => 0.2],
        "UI" => ["N" => 0.0, "P" => 0.1, "A" => 0.2],
        "AC" => ['L' => 0.0, 'H' => 0.1],
        "AT" => ['N' => 0.0, 'P' => 0.1],
        "VC" => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        "VI" => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        "VA" => ['H' => 0.0, 'L' => 0.1, 'N' => 0.2],
        "SC" => ['H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        "SI" => ['S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        "SA" => ['S' => 0.0, 'H' => 0.1, 'L' => 0.2, 'N' => 0.3],
        "CR" => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        "IR" => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        "AR" => ['H' => 0.0, 'M' => 0.1, 'L' => 0.2],
        "E" => ['U' => 0.2, 'P' => 0.1, 'A' => 0.0],
    ];

    public static array $MAX_COMPOSED = [
        'eq1' => [
            0 => ["AV:N/PR:N/UI:N/"],
            1 => ["AV:A/PR:N/UI:N/", "AV:N/PR:L/UI:N/", "AV:N/PR:N/UI:P/"],
            2 => ["AV:P/PR:N/UI:N/", "AV:A/PR:L/UI:P/"]
        ],
        'eq2' => [
            0 => ["AC:L/AT:N/"],
            1 => ["AC:H/AT:N/", "AC:L/AT:P/"]
        ],
        'eq3' => [
            0 => [
                '0' => ["VC:H/VI:H/VA:H/CR:H/IR:H/AR:H/"],
                '1' => ["VC:H/VI:H/VA:L/CR:M/IR:M/AR:H/", "VC:H/VI:H/VA:H/CR:M/IR:M/AR:M/"]
            ],
            1 => [
                '0' => ["VC:L/VI:H/VA:H/CR:H/IR:H/AR:H/", "VC:H/VI:L/VA:H/CR:H/IR:H/AR:H/"],
                '1' => ["VC:L/VI:H/VA:L/CR:H/IR:M/AR:H/", "VC:L/VI:H/VA:H/CR:H/IR:M/AR:M/", "VC:H/VI:L/VA:H/CR:M/IR:H/AR:M/", "VC:H/VI:L/VA:L/CR:M/IR:H/AR:H/", "VC:L/VI:L/VA:H/CR:H/IR:H/AR:M/"]
            ],
            2 => [
                '1' => ["VC:L/VI:L/VA:L/CR:H/IR:H/AR:H/"]
            ]
        ],
        'eq4' => [
            0 => ["SC:H/SI:S/SA:S/"],
            1 => ["SC:H/SI:H/SA:H/"],
            2 => ["SC:L/SI:L/SA:L/"]
        ],
        'eq5' => [
            0 => ["E:A/"],
            1 => ["E:P/"],
            2 => ["E:U/"]
        ],
    ];

    public static array $MAX_SEVERITY = [
        'eq1' => [0 => 1, 1 => 4, 2 => 5],
        'eq2' => [0 => 1, 1 => 2],
        'eq3eq6' => [
            0 => [0 => 7, 1 => 6],
            1 => [0 => 8, 1 => 8],
            2 => [1 => 10]
        ],
        'eq4' => [0 => 6, 1 => 5, 2 => 4],
        'eq5' => [0 => 1, 1 => 1, 2 => 1],
    ];

    public function calculateSeverityRating(float $score): string
    {
        if ($score === 0.0) return 'None';
        if ($score >= 0.1 && $score <= 3.9) return 'Low';
        if ($score >= 4.0 && $score <= 6.9) return 'Medium';
        if ($score >= 7.0 && $score <= 8.9) return 'High';
        if ($score >= 9.0 && $score <= 10.0) return 'Critical';
        return 'Unknown';
    }

    private function parseVectorToMap(string $str): array
    {
        $map = [];
        $parts = explode('/', $str);
        foreach ($parts as $part) {
            if ($part === '' || strpos($part, ':') === false) continue;
            [$metric, $value] = explode(':', $part, 2);
            $map[$metric] = $value;
        }
        return $map;
    }

    public function calculateSeverityDistances(string $maxVector): array
    {
        $parsed = $this->parseVectorToMap($maxVector);
        $distances = [];
        foreach (self::$METRIC_LEVELS as $metric => $levels) {
            $effectiveValue = $this->getEffectiveMetricValue($metric);
            $extractedValue = $parsed[$metric] ?? '';
            $distances[$metric] = (self::$METRIC_LEVELS[$metric][$effectiveValue] ?? 0) - (self::$METRIC_LEVELS[$metric][$extractedValue] ?? 0);
        }
        return $distances;
    }

    public function extractValueMetric(string $metric, string $str): string
    {
        $pos = strpos($str, $metric . ':');
        if ($pos === false) return '';
        $start = $pos + strlen($metric) + 1;
        $substr = substr($str, $start);
        $slashPos = strpos($substr, '/');
        return $slashPos !== false ? substr($substr, 0, $slashPos) : $substr;
    }

    public function getMaxSeverityVectorsForEQ(string $macroVector, int $eqNumber)
    {
        $index = (int) $macroVector[$eqNumber - 1];
        return self::$MAX_COMPOSED['eq' . $eqNumber][$index];
    }

    public function calculateScore(): float
    {
        $noImpactMetrics = ["VC", "VI", "VA", "SC", "SI", "SA"];
        foreach ($noImpactMetrics as $m) {
            if ($this->getEffectiveMetricValue($m) !== 'N') {
                $allNone = false;
                break;
            }
            $allNone = true;
        }
        if (isset($allNone) && $allNone === true) {
            return 0.0;
        }

        $equivalentClasses = $this->getEquivalentClasses();
        $value = self::$LOOKUP_TABLE[$equivalentClasses] ?? 0.0;

        [$eq1, $eq2, $eq3, $eq4, $eq5, $eq6] = array_map('intval', str_split($equivalentClasses));

        $eq1_next = ($eq1 + 1) . $eq2 . $eq3 . $eq4 . $eq5 . $eq6;
        $eq2_next = $eq1 . ($eq2 + 1) . $eq3 . $eq4 . $eq5 . $eq6;
        $eq3eq6_next = null; $eq3eq6_next_left = null; $eq3eq6_next_right = null;
        if ($eq3 === 1 && $eq6 === 1) {
            $eq3eq6_next = $eq1 . $eq2 . ($eq3 + 1) . $eq4 . $eq5 . $eq6;
        } elseif ($eq3 === 0 && $eq6 === 1) {
            $eq3eq6_next = $eq1 . $eq2 . ($eq3 + 1) . $eq4 . $eq5 . $eq6;
        } elseif ($eq3 === 1 && $eq6 === 0) {
            $eq3eq6_next = $eq1 . $eq2 . $eq3 . $eq4 . $eq5 . ($eq6 + 1);
        } elseif ($eq3 === 0 && $eq6 === 0) {
            $eq3eq6_next_left = $eq1 . $eq2 . $eq3 . $eq4 . $eq5 . ($eq6 + 1);
            $eq3eq6_next_right = $eq1 . $eq2 . ($eq3 + 1) . $eq4 . $eq5 . $eq6;
        } else {
            $eq3eq6_next = $eq1 . $eq2 . ($eq3 + 1) . $eq4 . $eq5 . ($eq6 + 1);
        }

        $eq4_next = $eq1 . $eq2 . $eq3 . ($eq4 + 1) . $eq5 . $eq6;
        $eq5_next = $eq1 . $eq2 . $eq3 . $eq4 . ($eq5 + 1) . $eq6;

        $score_eq1_next = self::$LOOKUP_TABLE[$eq1_next] ?? NAN;
        $score_eq2_next = self::$LOOKUP_TABLE[$eq2_next] ?? NAN;
        if ($eq3 == 0 && $eq6 == 0) {
            $score_left = self::$LOOKUP_TABLE[$eq3eq6_next_left] ?? NAN;
            $score_right = self::$LOOKUP_TABLE[$eq3eq6_next_right] ?? NAN;
            $score_eq3eq6_next = max($score_left, $score_right);
        } else {
            $score_eq3eq6_next = self::$LOOKUP_TABLE[$eq3eq6_next] ?? NAN;
        }

        $score_eq4_next = self::$LOOKUP_TABLE[$eq4_next] ?? NAN;
        $score_eq5_next = self::$LOOKUP_TABLE[$eq5_next] ?? NAN;

        $eqMaxes = [
            $this->getMaxSeverityVectorsForEQ($equivalentClasses, 1),
            $this->getMaxSeverityVectorsForEQ($equivalentClasses, 2),
            $this->getMaxSeverityVectorsForEQ($equivalentClasses, 3)[$eq6],
            $this->getMaxSeverityVectorsForEQ($equivalentClasses, 4),
            $this->getMaxSeverityVectorsForEQ($equivalentClasses, 5),
        ];

        $maxVectors = [];
        foreach ($eqMaxes[0] as $eq1Max) {
            foreach ($eqMaxes[1] as $eq2Max) {
                foreach ($eqMaxes[2] as $eq3Max) {
                    foreach ($eqMaxes[3] as $eq4Max) {
                        foreach ($eqMaxes[4] as $eq5Max) {
                            $maxVectors[] = $eq1Max . $eq2Max . $eq3Max . $eq4Max . $eq5Max;
                        }
                    }
                }
            }
        }

        $maxVector = '';
        $distances = [];
        foreach ($maxVectors as $vector) {
            $distances = $this->calculateSeverityDistances($vector);
            $allNonNegative = true;
            foreach ($distances as $d) { if ($d < 0) { $allNonNegative = false; break; } }
            if ($allNonNegative) { $maxVector = $vector; break; }
        }

        $current_eq1 = ($distances["AV"] ?? 0) + ($distances["PR"] ?? 0) + ($distances["UI"] ?? 0);
        $current_eq2 = ($distances["AC"] ?? 0) + ($distances["AT"] ?? 0);
        $current_eq3eq6 = ($distances["VC"] ?? 0) + ($distances["VI"] ?? 0) + ($distances["VA"] ?? 0) + ($distances["CR"] ?? 0) + ($distances["IR"] ?? 0) + ($distances["AR"] ?? 0);
        $current_eq4 = ($distances["SC"] ?? 0) + ($distances["SI"] ?? 0) + ($distances["SA"] ?? 0);
        $current_eq5 = 0;

        $available_eq1 = $value - $score_eq1_next;
        $available_eq2 = $value - $score_eq2_next;
        $available_eq3eq6 = $value - $score_eq3eq6_next;
        $available_eq4 = $value - $score_eq4_next;
        $available_eq5 = $value - $score_eq5_next;

        $n_existing_lower = 0;
        $normalized_eq1 = 0; $normalized_eq2 = 0; $normalized_eq3eq6 = 0; $normalized_eq4 = 0; $normalized_eq5 = 0;
        $STEP = 0.1;
        $maxS_eq1 = (self::$MAX_SEVERITY['eq1'][$eq1] ?? 0) * $STEP;
        $maxS_eq2 = (self::$MAX_SEVERITY['eq2'][$eq2] ?? 0) * $STEP;
        $maxS_eq3eq6 = (self::$MAX_SEVERITY['eq3eq6'][$eq3][$eq6] ?? 0) * $STEP;
        $maxS_eq4 = (self::$MAX_SEVERITY['eq4'][$eq4] ?? 0) * $STEP;

        if (!is_nan($available_eq1)) { $n_existing_lower++; $normalized_eq1 = $available_eq1 * ($current_eq1 / ($maxS_eq1 ?: 1)); }
        if (!is_nan($available_eq2)) { $n_existing_lower++; $normalized_eq2 = $available_eq2 * ($current_eq2 / ($maxS_eq2 ?: 1)); }
        if (!is_nan($available_eq3eq6)) { $n_existing_lower++; $normalized_eq3eq6 = $available_eq3eq6 * ($current_eq3eq6 / ($maxS_eq3eq6 ?: 1)); }
        if (!is_nan($available_eq4)) { $n_existing_lower++; $normalized_eq4 = $available_eq4 * ($current_eq4 / ($maxS_eq4 ?: 1)); }
        if (!is_nan($available_eq5)) { $n_existing_lower++; $normalized_eq5 = 0; }

        $meanDistance = $n_existing_lower === 0 ? 0 : ($normalized_eq1 + $normalized_eq2 + $normalized_eq3eq6 + $normalized_eq4 + $normalized_eq5) / $n_existing_lower;
        $score = max(0, min(10, $value - $meanDistance));
        return $this->roundToDecimalPlaces($score);
    }

    public function getScore(): float
    {
        return $this->calculateScore();
    }

    public function getSeverity(): string
    {
        return $this->calculateSeverityRating($this->getScore());
    }

    public function calculate(Request $request)
    {
        $vector = (string) $request->input('vector', '');

        $instance = new self();
        if ($vector !== '') {
            try {
                $instance->updateMetricsFromVectorString($vector);
            } catch (\Exception $e) {
                return response()->json([
                    'error' => $e->getMessage(),
                ], 400);
            }
        }

        return response()->json([
            'raw' => $instance->getRawVector(),
            'equivalentClasses' => $instance->getEquivalentClasses(),
            'nomenclature' => $instance->getNomenclature(),
            'severityBreakdown' => $instance->getSeverityBreakdown(),
            'score' => $instance->getScore(),
            'severity' => $instance->getSeverity(),
            'metrics' => $instance->currentMetrics,
        ]);
    }

    public function metrics()
    {
        $path = base_path('resources/js/cvss4/metrics.json');
        if (!File::exists($path)) {
            return response()->json(['error' => 'metrics.json not found'], 404);
        }
        $json = File::get($path);
        return response($json, 200)->header('Content-Type', 'application/json');
    }
}

?>
