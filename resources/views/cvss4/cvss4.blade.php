<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, shrink-to-fit=no">
    <title>Common Vulnerability Scoring System Version 4.0 Calculator</title>
    <!-- External Libraries -->
    <script src="https://unpkg.com/vue@3.2.47/dist/vue.global.prod.js"></script>
    <!-- Stylesheets -->
    <link rel="stylesheet" href="https://unpkg.com/spectre.css@0.5.9/dist/spectre.min.css">
    <link rel="stylesheet" href="https://unpkg.com/spectre.css@0.5.9/dist/spectre-exp.min.css">
    <link rel="stylesheet" href="https://unpkg.com/spectre.css@0.5.9/dist/spectre-icons.min.css">
    {{-- <link rel="stylesheet" href="styles.css"> --}}
    <style>
        :root { --primary: #C11B05; }
        .metric-type h4 { background:linear-gradient(180deg,#f1f3f5,#e9ecef); border:1px solid #ced4da; border-radius:.5rem; padding:.6rem 1rem; box-shadow:0 1px 2px rgba(0,0,0,.06); }
        .metric-group { margin-top:1rem; }
        .metric-group > div { background:#f8f9fa; border:1px solid #dee2e6; border-radius:.75rem; box-shadow:0 1px 3px rgba(0,0,0,.08) inset; padding:.75rem; }
        .btn { border-radius:999px; }
        .columns { display:flex; flex-wrap:wrap; }
        .columns .col-3 { flex:0 0 25%; max-width:25%; }
        .columns .col-9 { flex:0 0 75%; max-width:75%; }
        .columns .col-2 { flex:0 0 16.6667%; max-width:16.6667%; }
        .columns .col-4 { flex:0 0 33.3333%; max-width:33.3333%; }
        .columns .col-6 { flex:0 0 50%; max-width:50%; }
        .columns .col-12 { flex:0 0 100%; max-width:100%; }
        .text-end { text-align:right !important; }
        .pe-2 { padding-right:.5rem !important; }
        .ps-2 { padding-left:.5rem !important; }
        /* Separadores de opciones */
        .metric-group .columns.row > [class^='col-'] { flex:0 0 auto; max-width:none; }
        .metric-group .columns.row > [class^='col-']:not(:last-child)::after { content: " | "; margin: 0 .5rem; color:#adb5bd; }
        /* Botones como texto, con pill al activo */
        .metric-group .columns.row > [class^='col-'] > button.btn {
            border:0; background:transparent; padding:.22rem .55rem; margin:0; transition:transform .2s ease, box-shadow .2s ease, background-color .2s ease, color .2s ease;
            border-radius:999px; position:relative; font-size:1rem;
        }
        .metric-group .columns.row > [class^='col-'] > button.btn-primary {
            color:#fff; background-image:linear-gradient(180deg, #e0341c, var(--primary));
            padding:.35rem 1rem; box-shadow:0 6px 14px rgba(193,27,5,.28), inset 0 -1px 0 rgba(255,255,255,.15);
            border:2px solid #9d1300; text-shadow:0 1px 0 rgba(0,0,0,.25);
            text-decoration: underline dotted rgba(255,255,255,.9); text-underline-offset:.2rem; text-decoration-thickness:2px;
        }
        .metric-group .columns.row > [class^='col-'] > button.btn-primary:hover { filter:brightness(1.03); transform:translateY(-1px); }
        .metric-group .columns.row > [class^='col-'] > button.btn-primary:active { transform:translateY(0); box-shadow:0 2px 6px rgba(193,27,5,.25); }
        .metric-group .columns.row > [class^='col-'] > button.btn-outline-secondary { color:#6c757d; border:2px solid #cfd4da; padding:.32rem .9rem; border-radius:999px; }
        .metric-group .columns.row > [class^='col-'] > button.btn-outline-secondary:hover {
            color:#343a40; background-color:#eef2f4; border-radius:999px; transform:translateY(-1px);
        }
        .metric-group .columns.row > [class^='col-'] > button.btn:focus-visible { outline: none; box-shadow:0 0 0 3px rgba(193,27,5,.25); }
        /* Subrayado punteado para etiquetas de la izquierda */
        .metric-group .columns .col-3.text-right.pr-2 abbr,
        .metric-group .columns .col-3.text-right.pr-2,
        .metric-group .columns .col-3.text-end.pe-2 abbr,
        .metric-group .columns .col-3.text-end.pe-2 { text-decoration: underline dotted; text-underline-offset: .2rem; }
        /* Centrado de página */
        #app { max-width: 1120px; margin: 0 auto; padding: .5rem; }
        body { background: radial-gradient(circle at 15% 10%, #ffffff, #f7f7f9); }
        /* Badges para severidad (cuando no hay Bootstrap) */
        .badge { display:inline-block; padding:.35rem .6rem; border-radius:.5rem; font-weight:600; }
        .bg-success { background:#198754; color:#fff; }
        .bg-warning { background:#ffc107; color:#212529; }
        .bg-danger { background:var(--primary); color:#fff; }
        .bg-secondary { background:#6c757d; color:#fff; }
        .score-pill { display:inline-flex; align-items:center; gap:.4rem; background:#f4f2ff; color:#222; padding:.25rem .6rem; border-radius:999px; box-shadow:inset 0 1px 0 rgba(255,255,255,.6); }
        .score-dot { width:.5rem; height:.5rem; border-radius:50%; background:#5b61ff; display:inline-block; }
    </style>
    @vite(['resources/js/cvss4/app.js', 'resources/css/styles.css'])
    <link rel="icon" href="data:,">
</head>
<body>
    <div id="app" class="container">
        <!-- Header Section -->
        <header id="header">
            <img alt="CVSS logo" src="https://first.org/cvss/identity/cvssv4_web.png" width="125">
            <h3 class="page-title">Common Vulnerability Scoring System Version 4.0 Calculator</h3>
            <mark
                class="tooltip c-hand"
                aria-label="Click to copy vector to clipboard"
                data-tooltip="Click vector to copy to clipboard"
                role="button"
                tabindex="0"
                @click="copyVector">
                @{{ vector }}
            </mark>
            <button class="btn btn-sm ml-2" @click="onReset()">Reset</button>
            <h5 class="score-line">
                <span
                    class="tooltip tooltip-bottom c-hand"
                    :data-tooltip="showDetails ? 'Hide details' : 'Show details'"
                    :aria-label="showDetails ? 'Hide details' : 'Show details'"
                    role="button"
                    tabindex="0"
                    @click="showDetails = !showDetails">
                    CVSS v4.0 Score:
                    <span class="score-pill"><span class="score-dot"></span> @{{ score }} / @{{ severityRating }}</span>
                    <span v-if="!showDetails"> ⊕</span>
                    <span v-else> ⊖</span>
                </span>
            </h5>

            <blockquote v-if="showDetails">
                <sup class="mb-2"><i>Macro vector: @{{ macroVector }}</i></sup>
                <div v-if="apiResult && apiResult.severityBreakdown">
                    <div v-for="(severity, description) in apiResult.severityBreakdown" :key="description">
                        @{{ description }}: @{{ severity }}
                    </div>
                </div>
            </blockquote>

        </header>

        <!-- Metrics Section -->
        <main class="columns" :style="{'margin-top': header_height + 10 + 'px'}">
            <h6 id="cvssReference" style="width: 100%; max-width: 1065px; margin: 10px;">
                Hover over metric names and metric values for a summary of the information in the official
                <a href="https://www.first.org/cvss/v4.0/specification-document" target="_blank">
                    CVSS v4.0 Specification Document
                </a>.
                The Specification is available along with a
                <a href="https://www.first.org/cvss/v4.0/user-guide" target="_blank">
                    User Guide
                </a>
                providing additional scoring guidance, an
                <a href="https://www.first.org/cvss/v4.0/examples" target="_blank">
                    Examples document
                </a>
                of scored vulnerabilities, a set of
                <a href="https://www.first.org/cvss/v4.0/faq" target="_blank">
                    Frequently Asked Questions (FAQ)
                </a>, and both JSON and XML Data Representations for all versions of CVSS, including the
                <a href="https://www.first.org/cvss/cvss-v4.0.json" target="_blank">
                    JSON format
                </a>.
            </h6>
            <div class="column col-10 col-xl-12">
                <div class="metric-type" v-for="(metricTypeData, metricType) in cvssConfigData">
                    <h4 class="text-center">
                        @{{ metricType }}
                        <span class="tooltip tooltip-left c-hand text-small" :data-tooltip="'This category should be filled \n by the ' + metricTypeData.fill">
                            <sup>?</sup>
                        </span>
                    </h4>
                    <div class="metric-group" v-for="(metricGroupData, metricGroup) in metricTypeData.metric_groups">
                        <h5 class="text-center">@{{ metricGroup }}</h5>
                        <div>
                            <!-- Metric Selection -->
                            <div class="" v-for="(metricData, metric) in metricGroupData">

                                <!-- Multiple ways of rendering metrics based on screen size -->
                                <div class="columns hide-xl mb-2">
                                    <div class="col-3 text-right pr-2" v-if="metricData.tooltip"><abbr :title="metricData.tooltip">@{{ metric }}</abbr>:</div>
                                    <div class="col-3 text-right pr-2" v-else>@{{ metric }}:</div>

                                    <div class="col-9 columns">
                                        <div class="col-2 pl-2" v-for="(optionData, option) in metricData.options">
                                            <button :class="buttonClass(selectedMetrics[metricData.short] === optionData.value)" v-if="option"
                                                    @click="onButton(metricData.short, optionData.value)">
                                                <abbr v-if="optionData.tooltip" :title="optionData.tooltip">@{{ option }}</abbr>
                                                <span v-else>@{{ option }}</span>
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div class="show-xl hide-lg">
                                    <div class="mb-1" v-if="metricData.tooltip"><abbr :title="metricData.tooltip">@{{ metric }}</abbr>:</div>
                                    <div class="mb-1" v-else>@{{ metric }}:</div>

                                    <div class="columns">
                                        <div class="col-2 pl-2" v-for="(optionData, option) in metricData.options">
                                            <button :class="buttonClass(selectedMetrics[metricData.short] === optionData.value)" v-if="option"
                                                    @click="onButton(metricData.short, optionData.value)">
                                                <abbr v-if="optionData.tooltip" :title="optionData.tooltip">@{{ option }}</abbr>
                                                <span v-else>@{{ option }}</span>
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div class="show-lg hide-md">
                                    <div class="mb-1" v-if="metricData.tooltip"><abbr :title="metricData.tooltip">@{{ metric }}</abbr>:</div>
                                    <div class="mb-1" v-else>@{{ metric }}:</div>

                                    <div class="columns pl-2">
                                        <div class="col-4 pb-2 pr-2" v-for="(optionData, option) in metricData.options">
                                            <button :class="buttonClass(selectedMetrics[metricData.short] === optionData.value)" v-if="option"
                                                    @click="onButton(metricData.short, optionData.value)">
                                                <abbr v-if="optionData.tooltip" :title="optionData.tooltip">@{{ option }}</abbr>
                                                <span v-else>@{{ option }}</span>
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div class="show-md hide-sm">
                                    <div class="mb-1" v-if="metricData.tooltip"><abbr :title="metricData.tooltip">@{{ metric }}</abbr>:</div>
                                    <div class="mb-1" v-else>@{{ metric }}:</div>

                                    <div class="columns pl-2">
                                        <div class="col-6 pb-2 pr-2" v-for="(optionData, option) in metricData.options">
                                            <button :class="buttonClass(selectedMetrics[metricData.short] === optionData.value)" v-if="option"
                                                    @click="onButton(metricData.short, optionData.value)">
                                                <abbr v-if="optionData.tooltip" :title="optionData.tooltip">@{{ option }}</abbr>
                                                <span v-else>@{{ option }}</span>
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                <div class="show-sm">
                                    <div class="mb-1" v-if="metricData.tooltip"><abbr :title="metricData.tooltip">@{{ metric }}</abbr>:</div>
                                    <div class="mb-1" v-else>@{{ metric }}:</div>

                                    <div class="columns pl-2">
                                        <div class="col-12 pb-2 pr-2" v-for="(optionData, option) in metricData.options">
                                            <button :class="buttonClass(selectedMetrics[metricData.short] === optionData.value, true)" v-if="option"
                                                    @click="onButton(metricData.short, optionData.value)">
                                                <abbr v-if="optionData.tooltip" :title="optionData.tooltip">@{{ option }}</abbr>
                                                <span v-else>@{{ option }}</span>
                                            </button>
                                        </div>
                                    </div>
                                </div>

                            </div>

                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>
</body>
</html>

