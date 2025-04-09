<script>
  class AdvancedReportGenerator {
    constructor(results) {
      this.results = results;
    }

    // Helper: Format numbers with commas
    formatNumber(num) {
      return num.toLocaleString();
    }

    // Helper: Format percentage to one decimal
    formatPercent(n) {
      return (n).toFixed(1) + '%';
    }

    // Helper: Create an HTML section with title and content
    createSection(title, content) {
      return `<h3 class="mt-6 text-xl font-bold text-gray-800">${title}</h3>
              <p class="mt-2 text-sm text-gray-700">${content}</p>`;
    }

    // Advanced Report Generation
    generateReport() {
      if (!this.results) {
        return "<p class='text-sm text-gray-600'>No analysis results available. Please run an analysis first.</p>";
      }

      const stats = this.results.stats;
      const totalEntries = stats.totalLines || 0;
      const uniqueIPs = stats.uniqueIPCount || (this.results.ipActivity ? Object.keys(this.results.ipActivity).length : 0);
      const threatScore = this.results.threatScore || 0;
      const threatLevel = this.results.threatLevel || "Low";
      const keyFindings = this.results.keySummaryFindings || [];
      const events = this.results.events || [];
      const ipActivity = this.results.ipActivity || {};
      const correlation = this.results.correlation || {};

      let report = `<div class="space-y-4">`;

      // Title and Generation Info
      report += `<h1 class="text-3xl font-bold">IIS Log Analyzer Advanced Report</h1>
                 <p class="text-sm text-gray-600">Report generated on ${new Date().toLocaleString()} | Version ${this.results.version}</p>`;

      // Overview Section
      report += this.createSection("Overview",
        `The analysis processed ${this.formatNumber(totalEntries)} log entries and identified ${this.formatNumber(uniqueIPs)} unique IP addresses. The overall threat score is ${threatScore} (${threatLevel.toUpperCase()}).`
      );

      // Security Events Analysis
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Security Events Analysis</h3>
                 <p class="mt-2 text-sm text-gray-700">
                   The system detected:
                   <ul class="list-disc pl-5">
                     <li>${this.formatNumber(stats.criticalEvents || 0)} critical security events</li>
                     <li>${this.formatNumber(stats.highEvents || 0)} high-severity events</li>
                     <li>${this.formatNumber(stats.mediumEvents || 0)} medium-severity events</li>
                     <li>${this.formatNumber(stats.lowEvents || 0)} low-severity events</li>
                   </ul>
                 </p>`;

      // Key Findings Section
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Key Findings</h3>`;
      if (keyFindings.length > 0) {
        report += `<ul class="list-disc pl-5 text-sm text-gray-700">`;
        keyFindings.forEach(finding => {
          report += `<li>${finding.description} (occurring ${finding.count} times)</li>`;
        });
        report += `</ul>`;
      } else {
        report += `<p class="text-sm text-gray-600">No standout key findings were flagged by the system.</p>`;
      }

      // IP Analysis Section
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">IP Analysis</h3>`;
      let suspiciousIPs = Object.entries(ipActivity)
                            .filter(([ip, data]) => data.malicious || data.scanner || (data.threatLevel && data.threatLevel > 0))
                            .map(([ip, data]) => {
                              const errorRate = data.requests ? (data.failedRequests / data.requests) * 100 : 0;
                              return {
                                ip,
                                requests: data.requests,
                                errorRate,
                                threatLevel: data.threatLevel || 0,
                                anomalyScore: data.anomalyScore || 0
                              };
                            });
      suspiciousIPs.sort((a, b) => b.threatLevel - a.threatLevel);
      if (suspiciousIPs.length > 0) {
        report += `<p class="text-sm text-gray-700">Some IP addresses showed suspicious behavior:</p><ul class="list-disc pl-5 text-sm text-gray-700">`;
        suspiciousIPs.slice(0, 5).forEach(ip => {
          report += `<li>IP <strong>${ip.ip}</strong> made ${this.formatNumber(ip.requests)} requests with an error rate of ${this.formatPercent(ip.errorRate)} and a threat level score of ${ip.threatLevel} (Anomaly Score: ${ip.anomalyScore}).</li>`;
        });
        report += `</ul>`;
      } else {
        report += `<p class="text-sm text-gray-600">No IP addresses were flagged as suspicious.</p>`;
      }

      // User Agent Analysis Section
      report += this.createSection("User Agent Analysis",
        `The system analyzed user agent strings and identified patterns for known web scanners, bots, and automation tools. Suspicious or risky user agents are flagged for further review. Check the User Agent analysis tab for a complete breakdown.`
      );

      // Correlation & Attack Chain Analysis Section
      const chainCount = (correlation.chains && correlation.chains.length) || 0;
      const campaignCount = (correlation.campaigns && correlation.campaigns.length) || 0;
      report += this.createSection("Correlation & Attack Chain Analysis",
        `Advanced correlation detected ${chainCount} attack chain patterns and ${campaignCount} distributed campaign patterns. ` +
        `These correlations combine events across reconnaissance, exploitation, and unauthorized access activity occurring in short timeframes to form coordinated attack patterns.`
      );

      // Additional Analysis: Traffic & Temporal Patterns
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Traffic and Temporal Patterns</h3>`;
      report += `<p class="mt-2 text-sm text-gray-700">
                  Analysis of the request patterns over time indicates that most activity occurs during business hours; however, there are notable bursts and off–hours events. 
                  These temporal patterns can help pinpoint coordinated or anomalous activities.
                </p>`;

      // Methodology and Caveats
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Methodology and Caveats</h3>`;
      report += `<p class="text-sm text-gray-700">
                  The advanced analysis leverages both signature–based detection and behavior–based heuristics. Confidence scores are dynamically calculated based on parameters such as request frequency, error rates, and event clustering. 
                  Please note that while the system is highly tuned, some detections may be false positives. It is advised that analysts perform manual reviews for alerts with lower confidence.
                </p>`;

      // Final Recommendations
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Final Summary and Recommendations</h3>`;
      report += `<p class="text-sm text-gray-700">
                  Overall, the threat level is ${threatLevel.toUpperCase()} with a calculated threat score of ${threatScore}. 
                  It is recommended to investigate the top flagged IPs and user agents, verify the correlated attack chains, and review anomalies flagged during off–hours or during traffic bursts. 
                  Maintain vigilance as some benign activity might trigger alerts—especially in dynamic environments.
                </p>`;

      report += `</div>`;
      return report;
    }
  }

  // Wire up the Advanced Report Generator button
  document.addEventListener('DOMContentLoaded', () => {
    const advancedReportBtn = document.getElementById('generateAdvancedReportBtn');
    if (advancedReportBtn) {
      advancedReportBtn.addEventListener('click', () => {
        // Assumes you already have a global variable (for example, in your UIController) that holds the analysis results.
        if (typeof uiController === 'undefined' || !uiController.results) {
          document.getElementById('advancedReportContent').innerHTML =
            '<p class="text-sm text-gray-600">No analysis results available yet. Please run an analysis first.</p>';
          return;
        }
        const reportGen = new AdvancedReportGenerator(uiController.results);
        const reportHTML = reportGen.generateReport();
        document.getElementById('advancedReportContent').innerHTML = reportHTML;
      });
    }
  });
</script>

<!-- Advanced Report Tab Content -->
<div id="advancedReport-tab" class="tab-content p-6 hidden">
  <h2 class="text-2xl font-bold text-gray-900 mb-4">IIS Log Analyzer Advanced Report</h2>
  <!-- This container will receive the fully formatted report -->
  <div id="advancedReportContent" class="prose prose-sm whitespace-pre-wrap bg-gray-50 p-4 rounded-md border border-gray-200 mb-4"></div>
  <button id="generateAdvancedReportBtn" 
          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
    Generate Advanced Report
  </button>
</div>
<!-- Advanced Report Tab Button -->
<button data-tab="advancedReport" class="tab">Advanced Report</button>

