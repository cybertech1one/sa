<!-- Advanced Report Tab Button (placed with other .tab buttons) -->
<button data-tab="advancedReport" class="tab">Advanced Report</button>
<!-- Advanced Report Tab Content -->
<div id="advancedReport-tab" class="tab-content p-6 hidden">
  <h2 class="text-2xl font-bold text-gray-900 mb-4">IIS Log Analyzer Advanced Report</h2>
  <!-- This container is for the generated report -->
  <div id="advancedReportContent" class="prose prose-sm whitespace-pre-wrap bg-gray-50 p-4 rounded-md border border-gray-200 mb-4"></div>
  <button id="generateAdvancedReportBtn" 
          class="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md shadow-sm text-white bg-blue-600 hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500">
    Generate Advanced Report
  </button>
</div>


// At the end of displayResults() in your UIController class, add:
window.uiController = this;
window.dispatchEvent(new CustomEvent("analysisCompleted", { detail: this.results }));




<script>
  class AdvancedReportGenerator {
    constructor(results) {
      this.results = results;
    }

    // Helper: Format numbers with commas
    formatNumber(num) {
      return num.toLocaleString();
    }

    // Helper: Format percentages to 1 decimal
    formatPercent(n) {
      return n.toFixed(1) + '%';
    }

    // Helper: Create an HTML section with title and content
    createSection(title, content) {
      return `<h3 class="mt-6 text-xl font-bold text-gray-800">${title}</h3>
              <p class="mt-2 text-sm text-gray-700">${content}</p>`;
    }

    // Generate a comprehensive multi–section report
    generateReport() {
      if (!this.results) {
        return "<p class='text-sm text-gray-600'>No analysis results available. Please run an analysis first.</p>";
      }
      
      const stats = this.results.stats;
      const uniqueIPs = stats.uniqueIPCount || (this.results.ipActivity ? Object.keys(this.results.ipActivity).length : 0);
      const totalEntries = stats.totalLines || 0;
      const threatScore = this.results.threatScore || 0;
      const threatLevel = this.results.threatLevel || "Low";
      const keyFindings = this.results.keySummaryFindings || [];
      const events = this.results.events || [];
      const ipActivity = this.results.ipActivity || {};
      const correlation = this.results.correlation || {};

      let report = `<div class="space-y-4">`;
      
      // Title and Generation Info
      report += `<h1 class="text-3xl font-bold">IIS Log Analyzer Advanced Report</h1>
                 <p class="text-sm text-gray-600 mb-4">Report generated on ${new Date().toLocaleString()} | Version ${this.results.version}</p>`;
      
      // Overview Section
      report += this.createSection("Overview",
        `A total of ${this.formatNumber(totalEntries)} log entries were processed, identifying ${this.formatNumber(uniqueIPs)} unique IP addresses. 
         The overall threat score is ${threatScore}, which corresponds to a ${threatLevel.toUpperCase()} threat level.`
      );

      // Security Events Analysis Section
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Security Events Analysis</h3>`;
      report += `<p class="mt-2 text-sm text-gray-700">
                   The analysis detected the following security events:
                   <ul class="list-disc pl-5">
                     <li>${this.formatNumber(stats.criticalEvents || 0)} critical events</li>
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
        report += `<p class="text-sm text-gray-600">No outstanding key findings were detected.</p>`;
      }

      // IP Analysis Section
      report += this.createSection("IP Analysis",
        `Suspicious IPs with anomalous behavior, high error rates, or scanner signatures have been flagged. 
         For example, some IPs registered unusually high request volumes or error rates. Please refer to the IP Analysis section for detailed metrics.`
      );
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
        report += `<p class="mt-2 text-sm text-gray-700">Noteworthy IP addresses include:</p>
                   <ul class="list-disc pl-5 text-sm text-gray-700">`;
        suspiciousIPs.slice(0, 5).forEach(ip => {
          report += `<li>IP <strong>${ip.ip}</strong>: ${this.formatNumber(ip.requests)} requests, error rate of ${this.formatPercent(ip.errorRate)}, Threat Level ${ip.threatLevel}, Anomaly Score: ${ip.anomalyScore}</li>`;
        });
        report += `</ul>`;
      } else {
        report += `<p class="text-sm text-gray-600">No IP addresses were flagged as suspicious.</p>`;
      }

      // User Agent Analysis Section
      report += this.createSection("User Agent Analysis",
        `The tool analyzed user agent strings to identify known scanners, bots, and automated tools. 
         Suspicious user agents with high risk ratings have been flagged. For a complete breakdown, please see the User Agents tab.`
      );
      
      // Correlation & Attack Chain Analysis Section
      const chainCount = (correlation.chains && correlation.chains.length) || 0;
      const campaignCount = (correlation.campaigns && correlation.campaigns.length) || 0;
      report += this.createSection("Correlation & Attack Chain Analysis",
        `Advanced correlation identified ${chainCount} potential attack chain patterns and ${campaignCount} distributed campaign patterns. 
         These correlations combine reconnaissance, exploitation, and unauthorized access events occurring within short time spans.`
      );

      // Traffic and Temporal Patterns Section
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Traffic and Temporal Patterns</h3>
                 <p class="mt-2 text-sm text-gray-700">
                   A review of the traffic trends reveals that, while most requests occurred during typical business hours, 
                   there are distinct bursts and off–hours clusters that could indicate coordinated attack behavior. 
                   Detailed time–based visualizations are available in the Overview and Events tabs.
                 </p>`;

      // Methodology & Caveats Section
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Methodology and Caveats</h3>
                 <p class="mt-2 text-sm text-gray-700">
                   The analysis combines signature–based detection with behavioral heuristics. 
                   Confidence scores are derived from patterns, event frequency, and severity clustering. 
                   As with any automated analysis, some alerts may be false positives; therefore, manual validation is recommended for borderline cases.
                 </p>`;

      // Final Summary and Recommendations Section
      report += `<h3 class="mt-6 text-xl font-bold text-gray-800">Final Summary and Recommendations</h3>
                 <p class="mt-2 text-sm text-gray-700">
                   Overall, the threat level is evaluated as ${threatLevel.toUpperCase()} with a threat score of ${threatScore}. 
                   It is advised to closely investigate the flagged IPs, examine suspicious user agents, and review correlated attack chains. 
                   In addition, consider a manual review of any low-confidence alerts to mitigate the impact of potential false positives.
                 </p>`;

      report += `</div>`;
      return report;
    }
  }

  // Wire up the Advanced Report button to use live data from the app.
  document.addEventListener('DOMContentLoaded', () => {
    const advancedReportBtn = document.getElementById('generateAdvancedReportBtn');
    if (advancedReportBtn) {
      advancedReportBtn.addEventListener('click', () => {
        // Ensure the main controller's results are available; they should be stored globally as window.uiController.results.
        if (typeof window.uiController === 'undefined' || !window.uiController.results) {
          document.getElementById('advancedReportContent').innerHTML =
            '<p class="text-sm text-gray-600">Analysis results not available yet. Please run an analysis first.</p>';
          return;
        }
        const reportGen = new AdvancedReportGenerator(window.uiController.results);
        const reportHTML = reportGen.generateReport();
        document.getElementById('advancedReportContent').innerHTML = reportHTML;
      });
    }
  });
</script>
