const app = Vue.createApp({
    data() {
        return {
            cvssConfigData: null, // Contiene los datos de configuración cargados desde metrics.json
            showDetails: false, // Booleano para controlar la visibilidad de la información métrica detallada
            header_height: 0, // Almacena la altura del elemento de encabezado, útil para diseño responsivo
            macroVector: null, // Almacena la representación vectorial resumida
            selectedMetrics: {}, // Estado local de métricas seleccionadas
            apiResult: null, // Último resultado del backend
            isUpdating: false, // Flag para evitar doble fetch y permitir UI optimista
            abortController: null, // Controlador para abortar peticiones en curso
        };
    },
    methods: {
        /**
         * Obtiene y carga los datos de confiración del archivo metrics.json
         * Inicializa las instancias de vector y CVSS después de cargar los datos.
         */
        async loadConfigData() {
            try {
                const response = await fetch('/cvss4/metrics.json');
                this.cvssConfigData = await response.json();
                await this.onReset();
            } catch (error) {
                console.error("Failed to load configuration data: ", error);
            }
        },
        /**
         * Genera clases CSS para los botones según sus propiedades. 
         * @param {bollean} isPrimary - Determina si el botón tiene el estilo principal.
         * @param {boolean} big - Opcional. Determina si el botón es grande.
         * @returns {string} - La cadena de clase CSS generada
         */
        buttonClass(isPrimary, big = false) {
            const size = 'btn-lg';
            const style = isPrimary ? 'btn-primary' : 'btn-outline-danger';
            return `btn ${style} ${size} me-2 mb-2`;
        },
        /**
         * Devuelve la clase CSS según la clasificación de gravedad. 
         * Asigna los niveles de gravedad a las clases CSS correspondientes.
         * @param {string} severetyRating - La clasificación de gravedad (LOW, MEDIUM, HIGH, CRITICAL)
         * @returns {string} - La cadena de clase CSS correspondiente
         */
        getSeverityClass(severityRating) {
            const severityClasses = {
                "Low": "badge bg-success",
                "Medium": "badge bg-warning text-dark",
                "High": "badge bg-danger",
                "Critical": "badge bg-danger fw-bold",
                "None": "badge bg-secondary"
            };
            return severityClasses[severityRating] || "badge bg-secondary";
        },
        /**
         * Copia la cadena vectorial CVSS actual al portapapeles ya ctualiza el hash de la URL.
         */
        copyVector() {
            navigator.clipboard.writeText(this.vector); // Copiar vector al portapapeles
            window.location.hash = this.vector; // Actualizar el hash de la URL con el vector
        },
        /**
         * Gestiona las actualizaciones de métricas activadas al hacer clic en un botón.
         * Actualiza la instancia de Vector y actualiza la instancia de CVSS y la URL.
         * @param {string} metric - La métrica que se actualiza. 
         * @param {string} value - El nuevo valor de la métrica
         */
        onButton(metric, value) {
            this.selectedMetrics[metric] = value;
            const vector = this.buildVectorFromSelected(this.selectedMetrics);
            this.isUpdating = true;
            if (this.apiResult) this.apiResult = { ...this.apiResult, raw: vector };
            window.location.hash = vector;
            this.updateCVSSInstance(vector);
        },
        /**
         * Actualiza los estados de los botones según la cadena vectorial proporcionada. 
         * También actualiza la instancia CVSS para reflejar el nuevo estado vectorial. 
         * @param {string} vector - La cadena vectorial CVSS que se establecerá.
         */
        async setButtonsToVector(vector) {
            if (!vector) return;
            try {
                if (this.apiResult) this.apiResult = { ...this.apiResult, raw: vector };
                await this.updateCVSSInstance(vector);
            } catch (error) {
                console.error("Error updating vector: ", error.message);
            }
        },
        /**
         * Inicializa o actualiza la instancia CVSS según el vector actual.
         * También actualiza la representación del macrovector.
         */
        async updateCVSSInstance(vector) {
            const url = `/cvss4/calculate${vector ? `?vector=${encodeURIComponent(vector)}` : ''}`;
            if (this.abortController) {
                try { this.abortController.abort(); } catch (e) {}
            }
            this.abortController = new AbortController();
            const res = await fetch(url, { signal: this.abortController.signal });
            const data = await res.json();
            if (data.error) throw new Error(data.error);
            this.apiResult = data;
            this.selectedMetrics = { ...data.metrics };
            this.macroVector = data.equivalentClasses;
            this.isUpdating = false;
        },
        /**
         * Restablece la instancia de vector a su estado predeterminado y borra el hash de la URL
         */
        async onReset() {
            window.location.hash = "";
            this.selectedMetrics = {};
            await this.updateCVSSInstance("");
        },
        /**
         * Restablece la instancia del vector a un objeto vector predeterminado
         */
        resetSelected() {
            this.selectedMetrics = {};
        },
        buildVectorFromSelected(selected) {
            const parts = Object.entries(selected)
                .filter(([, v]) => v !== 'X' && v)
                .map(([k, v]) => `${k}:${v}`);
            return `CVSS:4.0/${parts.join('/')}`;
        },
        /**
         * Divide un objeto en fragmentos de un tamaño específico.
         * Útil para dividir datos en partes manejables para su visualización.
         * @param {oject} oject . El objeto a dividir
         * @param {number} chunkSize - El tamaño de cada fragmento
         * @returns {array} - Un array de fragmentos, cada uno co un parte del objeto original
         */
        splitObjectEntries(object, chunkSize) {
            return Object.entries(object).reduce((result, entry, index) => {
                if (index % chunkSize === 0) result.push([]); // Comenzar una nueva porción
                result[result.length - 1].push(entry); // Agregar entrada al fragmento actual
                return result;
            }, []);
        }
    },
    computed: {
        /**
         * Calcula la cadena vectorial actual a partir de la instancia de Vector.
         * @returns {string} - La cadena vectorial CVSS sin procesar
         */
        vector() {
            return this.apiResult ? this.apiResult.raw : 'CVSS:4.0';
        },
        /**
         * Calcula la puntuación CVSS actual basándose en la instancia CVSS.
         * @returns {number} - La puntuación CVSS calculada
         */
        score() {
            return this.apiResult ? this.apiResult.score : 0;
        },
        /**
         * Calcula la clasificación de gravedad actual según la instancia de CVSS. 
         * @returns {string} - La clasificación de gravedad (ej: "Low", "High")
         */
        severityRating() {
            return this.apiResult ? this.apiResult.severity : "None";
        }
    },
    async beforeMount() {
        await this.loadConfigData();
        await this.setButtonsToVector(window.location.hash.slice(1));
    },
    mounted() {
        // Escuche los cambios de hash de la URL y actualice el vector en consecuencia
        window.addEventListener("hashchange", () => {
            if (this.isUpdating) return;
            this.setButtonsToVector(window.location.hash.slice(1));
        });

        // Configurar un observador de cambio de tamaño para rastrear los cambios en la altura del encabezado
        const headerElement = document.getElementById('header');
        if (headerElement) {
            const resizeObserver = new ResizeObserver(() => {
                this.header_height = headerElement.clientHeight;
            });
            resizeObserver.observe(headerElement);
        } else {
            console.error("Header element not found");
        }

        if (window.bootstrap) {
            document.querySelectorAll('[data-bs-toggle="tooltip"]').forEach((el) => {
                try { new bootstrap.Tooltip(el); } catch (e) {}
            });
        }
    }
});

app.mount("#app");
