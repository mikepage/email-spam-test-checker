import { useSignal } from "@preact/signals";

interface SpamRule {
  score: number;
  ruleName: string;
  description: string;
  isNotice: boolean;
}

interface DefaultRule {
  name: string;
  score: number;
  category: string;
  description: string;
}

// Default SpamAssassin rules from https://github.com/apache/spamassassin/tree/trunk/rulesrc/scores
const DEFAULT_RULES: DefaultRule[] = [
  // Critical / Test Rules
  { name: "GTUBE", score: 1000.0, category: "Test", description: "Generic Test for Unsolicited Bulk Email" },

  // High-Impact Spam Rules (4.0+)
  { name: "KB_RATWARE_OUTLOOK_MID", score: 4.4, category: "Forgery", description: "Ratware Message-ID pretending to be Outlook" },
  { name: "HELO_DYNAMIC_HCC", score: 4.3, category: "Network", description: "HELO contains dynamic IP pattern" },
  { name: "HK_NAME_DRUGS", score: 4.3, category: "Content", description: "Pharmaceutical spam keywords in sender name" },
  { name: "BITCOIN_EXTORT_01", score: 4.1, category: "Scam", description: "Bitcoin extortion/sextortion attempt" },
  { name: "KB_RATWARE_MSGID", score: 4.1, category: "Forgery", description: "Ratware-style Message-ID detected" },
  { name: "URI_PHISH", score: 4.0, category: "Phishing", description: "URI found in phishing database" },
  { name: "FORGED_MUA_OUTLOOK", score: 4.0, category: "Forgery", description: "Forged Outlook mail user agent" },

  // High-Impact Rules (3.0-3.9)
  { name: "FSL_INTERIA_ABUSE", score: 3.9, category: "Network", description: "Sent from known abuse source" },
  { name: "MSGID_OUTLOOK_INVALID", score: 3.9, category: "Forgery", description: "Invalid Outlook Message-ID format" },
  { name: "KB_DATE_CONTAINS_TAB", score: 3.8, category: "Header", description: "Date header contains tab character" },
  { name: "FILL_THIS_FORM_LONG", score: 3.8, category: "Phishing", description: "Contains form-filling phishing text" },
  { name: "DOS_BODY_HIGH_NO_MID", score: 3.8, category: "Header", description: "High body score with no Message-ID" },
  { name: "HTML_SHORT_CENTER", score: 3.8, category: "HTML", description: "Short HTML message with centered text" },
  { name: "PHISH_AZURE_CLOUDAPP", score: 3.5, category: "Phishing", description: "Link to Azure cloudapp phishing site" },
  { name: "BITCOIN_MALF_HTML", score: 3.5, category: "Scam", description: "Bitcoin malware/scam in HTML content" },
  { name: "ADVANCE_FEE_3_NEW", score: 3.5, category: "Scam", description: "Advance fee fraud (419 scam) patterns" },
  { name: "FSL_HAS_TINYURL", score: 3.5, category: "URI", description: "Contains TinyURL shortened link" },
  { name: "HTML_TEXT_INVISIBLE_STYLE", score: 3.5, category: "HTML", description: "Invisible text using CSS styling" },
  { name: "URI_WP_DIRINDEX", score: 3.5, category: "URI", description: "WordPress directory index exploit" },
  { name: "PDS_FROM_2_EMAILS", score: 3.5, category: "Header", description: "From header contains two email addresses" },
  { name: "REPLICA_WATCH", score: 3.5, category: "Content", description: "Replica watch spam keywords" },
  { name: "SCC_CANSPAM_2", score: 3.4, category: "Legal", description: "Missing CAN-SPAM compliance elements" },
  { name: "FROM_MISSP_FREEMAIL", score: 3.4, category: "Forgery", description: "Misspelled freemail provider in From" },
  { name: "TO_EQ_FM_HTML_ONLY", score: 3.4, category: "Header", description: "To equals From, HTML only message" },
  { name: "FROM_MISSP_PHISH", score: 3.2, category: "Phishing", description: "Misspelled domain in From (phishing)" },
  { name: "MALE_ENHANCE", score: 3.1, category: "Content", description: "Male enhancement spam keywords" },
  { name: "UNDISC_MONEY", score: 3.1, category: "Scam", description: "Undisclosed money transfer scam" },
  { name: "DEAR_WINNER", score: 3.1, category: "Scam", description: "Lottery/prize winner scam" },
  { name: "FROM_UNBAL2", score: 3.1, category: "Header", description: "Unbalanced quotes in From header" },
  { name: "UNDISC_FREEM", score: 3.1, category: "Header", description: "Undisclosed recipients from freemail" },
  { name: "FORGED_MUA_THEBAT_BOUN", score: 3.0, category: "Forgery", description: "Forged The Bat! mailer bounce" },
  { name: "IMG_DIRECT_TO_MX", score: 3.0, category: "URI", description: "Image links directly to mail server" },
  { name: "LONG_INVISIBLE_TEXT", score: 3.0, category: "HTML", description: "Long sections of invisible text" },
  { name: "ACCT_PHISHING_MANY", score: 3.0, category: "Phishing", description: "Multiple account phishing indicators" },
  { name: "URI_EXCESS_SLASHES", score: 3.0, category: "URI", description: "Excessive slashes in URI (obfuscation)" },
  { name: "URI_FIREBASEAPP", score: 3.0, category: "Phishing", description: "Firebase app link (often phishing)" },
  { name: "GOOG_STO_EMAIL_PHISH", score: 3.0, category: "Phishing", description: "Google storage email phishing" },
  { name: "HTML_ENTITY_ASCII", score: 3.0, category: "HTML", description: "HTML entities for ASCII obfuscation" },
  { name: "MONEY_FORM", score: 3.1, category: "Scam", description: "Money transfer form scam" },

  // Medium-High Rules (2.0-2.9)
  { name: "DOS_OE_TO_MX_IMAGE", score: 2.9, category: "Network", description: "Outlook Express to MX with image" },
  { name: "X_MAILER_CME_6543_MSN", score: 2.9, category: "Forgery", description: "Forged MSN mailer header" },
  { name: "MISSING_MID", score: 2.5, category: "Header", description: "Missing Message-ID header" },
  { name: "TVD_PH_1", score: 2.3, category: "Phishing", description: "Phishing pattern detected" },
  { name: "FUZZY_CREDIT", score: 2.3, category: "Content", description: "Fuzzy match on credit card terms" },
  { name: "SUBJ_ALL_CAPS", score: 2.2, category: "Header", description: "Subject is all capital letters" },
  { name: "FROM_EXCESS_BASE64", score: 2.1, category: "Header", description: "Excessive Base64 in From header" },
  { name: "FUZZY_AMBIEN", score: 2.1, category: "Content", description: "Fuzzy match on pharmaceutical terms" },
  { name: "RCVD_IN_BL_SPAMCOP_NET", score: 2.0, category: "Network", description: "Listed in SpamCop blocklist" },
  { name: "RCVD_IN_XBL", score: 2.0, category: "Network", description: "Listed in Spamhaus XBL" },

  // Medium Rules (1.0-1.9)
  { name: "HTML_MESSAGE", score: 1.8, category: "Format", description: "HTML message (no plain text)" },
  { name: "MISSING_HEADERS", score: 1.7, category: "Header", description: "Missing essential headers" },
  { name: "FORGED_OUTLOOK_HTML", score: 1.6, category: "Forgery", description: "Outlook HTML signature forged" },
  { name: "MIME_HTML_ONLY", score: 1.5, category: "Format", description: "MIME HTML only, no text part" },
  { name: "RCVD_IN_SBL", score: 1.5, category: "Network", description: "Listed in Spamhaus SBL" },
  { name: "RCVD_IN_PBL", score: 1.3, category: "Network", description: "Listed in Spamhaus PBL" },
  { name: "SPF_FAIL", score: 1.2, category: "Auth", description: "SPF check failed" },
  { name: "DKIM_INVALID", score: 1.0, category: "Auth", description: "DKIM signature invalid" },
  { name: "RDNS_NONE", score: 1.0, category: "Network", description: "No reverse DNS for sending IP" },
  { name: "URIBL_BLACK", score: 1.0, category: "URI", description: "URI in Spamhaus URIBL blacklist" },

  // Low Rules (0.1-0.9)
  { name: "BAYES_50", score: 0.8, category: "Bayes", description: "Bayesian spam probability 40-60%" },
  { name: "HTML_FONT_LOW_CONTRAST", score: 0.5, category: "HTML", description: "Low contrast font colors" },
  { name: "DKIM_SIGNED", score: 0.1, category: "Auth", description: "DKIM signature present (not validated)" },
  { name: "SPF_HELO_NONE", score: 0.1, category: "Auth", description: "No SPF record for HELO domain" },

  // Negative Scores (Ham Indicators)
  { name: "BAYES_00", score: -1.9, category: "Bayes", description: "Bayesian spam probability 0-1%" },
  { name: "BAYES_05", score: -0.5, category: "Bayes", description: "Bayesian spam probability 1-5%" },
  { name: "DKIM_VALID", score: -0.1, category: "Auth", description: "Valid DKIM signature" },
  { name: "DKIM_VALID_AU", score: -0.1, category: "Auth", description: "DKIM valid, author domain match" },
  { name: "DKIM_VALID_EF", score: -0.1, category: "Auth", description: "DKIM valid, envelope from match" },
  { name: "SPF_PASS", score: -0.1, category: "Auth", description: "SPF check passed" },
  { name: "ALL_TRUSTED", score: -1.0, category: "Network", description: "All relays are trusted" },
  { name: "RCVD_IN_DNSWL_NONE", score: -0.0, category: "Network", description: "Listed in DNSWL, no trust level" },
  { name: "RCVD_IN_DNSWL_LOW", score: -0.7, category: "Network", description: "Listed in DNSWL, low trust" },
  { name: "RCVD_IN_DNSWL_MED", score: -2.3, category: "Network", description: "Listed in DNSWL, medium trust" },
  { name: "RCVD_IN_DNSWL_HI", score: -5.0, category: "Network", description: "Listed in DNSWL, high trust" },
  { name: "RCVD_IN_MSPIKE_H2", score: -0.5, category: "Network", description: "Cloudmark Sender Intelligence good" },
  { name: "RCVD_IN_MSPIKE_H3", score: -1.0, category: "Network", description: "Cloudmark excellent reputation" },
  { name: "RCVD_IN_MSPIKE_H4", score: -2.0, category: "Network", description: "Cloudmark outstanding reputation" },
  { name: "USER_IN_WELCOMELIST", score: -100.0, category: "Whitelist", description: "Sender in user's welcomelist" },
  { name: "USER_IN_DEF_WELCOMELIST", score: -50.0, category: "Whitelist", description: "Sender in default welcomelist" },
];

interface AnalysisResult {
  rules: SpamRule[];
  totalScore: number;
  verdict: "clean" | "suspicious" | "spam";
}

const SAMPLE_INPUT = `0.0 ADMINISTRATOR NOTICE: The query to URIBL was blocked. See http://wiki.apache.org/spamassassin/DnsBlocklists#dnsbl-block for more information. [URIs: example.com]
0.0 RBL: ADMINISTRATOR NOTICE: The query to Validity was blocked. See https://knowledge.validity.com/hc/en-us/articles/20961730681243 for more information. [2a01:7c8:7c8::72 listed in bl.score.senderscore.com]
0.0 RBL: ADMINISTRATOR NOTICE: The query to Validity was blocked. See https://knowledge.validity.com/hc/en-us/articles/20961730681243 for more information. [2a01:7c8:7c8::72 listed in sa-trusted.bondedsender.org]
0.0 [URIs: example.com]
-0.0 RBL: Sender listed at https://www.dnswl.org/, no trust [2a01:7c8:7c8::72 listed in list.dnswl.org]
0.0 RBL:
0.0 [URIs: example.com]
0.1 Message has a DKIM or DK signature, not necessarily valid
0.1 DKIM or DK signature exists, but is not valid`;

function parseSpamRules(input: string): SpamRule[] {
  const lines = input.trim().split("\n");
  const rules: SpamRule[] = [];

  for (const line of lines) {
    const trimmedLine = line.trim();
    if (!trimmedLine) continue;

    // Match score at the beginning (handles -0.0, 0.0, 1.5, etc.)
    const scoreMatch = trimmedLine.match(/^(-?\d+\.?\d*)\s+(.*)$/);

    if (scoreMatch) {
      const score = parseFloat(scoreMatch[1]);
      const rest = scoreMatch[2].trim();

      // Check if it's an admin notice
      const isNotice = rest.includes("ADMINISTRATOR NOTICE");

      // Try to extract rule name and description
      let ruleName = "";
      let description = rest;

      // Common patterns: "RULE_NAME description" or "RBL: description"
      const ruleMatch = rest.match(/^([A-Z][A-Z0-9_]+:?)\s*(.*)$/);
      if (ruleMatch) {
        ruleName = ruleMatch[1].replace(/:$/, "");
        description = ruleMatch[2] || rest;
      } else if (rest.startsWith("[")) {
        // Just metadata like [URIs: domain.com]
        ruleName = "INFO";
        description = rest;
      } else {
        // Full description, try to create a rule name from it
        const words = rest.split(" ").slice(0, 3).join("_").toUpperCase().replace(/[^A-Z0-9_]/g, "");
        ruleName = words || "UNKNOWN";
        description = rest;
      }

      rules.push({
        score,
        ruleName,
        description,
        isNotice,
      });
    }
  }

  return rules;
}

function analyzeRules(rules: SpamRule[]): AnalysisResult {
  const totalScore = rules.reduce((sum, rule) => sum + rule.score, 0);

  let verdict: "clean" | "suspicious" | "spam";
  if (totalScore >= 5) {
    verdict = "spam";
  } else if (totalScore >= 2) {
    verdict = "suspicious";
  } else {
    verdict = "clean";
  }

  return {
    rules,
    totalScore,
    verdict,
  };
}

function getScoreColor(score: number): string {
  if (score > 0) return "text-red-600";
  if (score < 0) return "text-green-600";
  return "text-gray-500";
}

function getScoreBgColor(score: number): string {
  if (score > 0) return "bg-red-50";
  if (score < 0) return "bg-green-50";
  return "bg-gray-50";
}

function getVerdictStyle(verdict: "clean" | "suspicious" | "spam"): { bg: string; text: string; border: string } {
  switch (verdict) {
    case "clean":
      return { bg: "bg-green-50", text: "text-green-700", border: "border-green-200" };
    case "suspicious":
      return { bg: "bg-yellow-50", text: "text-yellow-700", border: "border-yellow-200" };
    case "spam":
      return { bg: "bg-red-50", text: "text-red-700", border: "border-red-200" };
  }
}

const RULE_CATEGORIES = [
  "All",
  "Auth",
  "Bayes",
  "Content",
  "Forgery",
  "Format",
  "Header",
  "HTML",
  "Legal",
  "Network",
  "Phishing",
  "Scam",
  "Test",
  "URI",
  "Whitelist",
] as const;

export default function SpamScoreChecker() {
  const inputText = useSignal("");
  const result = useSignal<AnalysisResult | null>(null);
  const showNotices = useSignal(true);
  const ruleSearch = useSignal("");
  const ruleCategory = useSignal<string>("All");

  const handleAnalyze = () => {
    if (!inputText.value.trim()) return;

    const rules = parseSpamRules(inputText.value);
    result.value = analyzeRules(rules);
  };

  const handleClear = () => {
    inputText.value = "";
    result.value = null;
  };

  const handleLoadSample = () => {
    inputText.value = SAMPLE_INPUT;
    result.value = null;
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const filteredRules = result.value?.rules.filter(
    (rule) => showNotices.value || !rule.isNotice
  ) ?? [];

  return (
    <div class="w-full max-w-4xl mx-auto">
      {/* Input Section */}
      <div class="mb-4">
        <label class="block text-sm font-medium text-gray-700 mb-1">
          SpamAssassin Report
        </label>
        <textarea
          value={inputText.value}
          onInput={(e) => inputText.value = (e.target as HTMLTextAreaElement).value}
          class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500 text-sm font-mono"
          placeholder="Paste SpamAssassin rules here...&#10;&#10;Example:&#10;0.0 RULE_NAME Description&#10;1.5 SPAM_RULE This is spam&#10;-0.5 HAM_RULE This is not spam"
          rows={8}
        />
      </div>

      {/* Options Section */}
      <div class="bg-gray-50 rounded-lg p-4 mb-4">
        <h3 class="text-sm font-medium text-gray-700 mb-3">Options</h3>
        <div class="flex flex-wrap gap-4">
          <label class="flex items-center gap-2 cursor-pointer">
            <input
              type="checkbox"
              checked={showNotices.value}
              onChange={(e) => showNotices.value = (e.target as HTMLInputElement).checked}
              class="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
            />
            <span class="text-sm text-gray-700">Show Administrator Notices</span>
          </label>
        </div>
      </div>

      {/* Action Buttons */}
      <div class="flex gap-3 mb-6">
        <button
          onClick={handleAnalyze}
          disabled={!inputText.value.trim()}
          class={`px-6 py-2 font-medium rounded-lg transition-colors ${
            !inputText.value.trim()
              ? "bg-gray-400 text-gray-200 cursor-not-allowed"
              : "bg-blue-600 text-white hover:bg-blue-700"
          }`}
        >
          Analyze
        </button>
        <button
          onClick={handleClear}
          class="px-4 py-2 bg-gray-200 text-gray-700 font-medium rounded-lg hover:bg-gray-300 transition-colors"
        >
          Clear
        </button>
        <button
          onClick={handleLoadSample}
          class="px-4 py-2 bg-gray-200 text-gray-700 font-medium rounded-lg hover:bg-gray-300 transition-colors"
        >
          Load Sample
        </button>
      </div>

      {/* Results Section */}
      {result.value && (
        <div class="space-y-4">
          {/* Summary Card */}
          {(() => {
            const style = getVerdictStyle(result.value.verdict);
            return (
              <div class={`rounded-lg shadow p-4 ${style.bg} border ${style.border}`}>
                <div class="flex items-center justify-between">
                  <div class="flex items-center gap-3">
                    <span class={`text-2xl font-bold ${style.text}`}>
                      {result.value.verdict === "clean" && "Clean"}
                      {result.value.verdict === "suspicious" && "Suspicious"}
                      {result.value.verdict === "spam" && "Likely Spam"}
                    </span>
                  </div>
                  <div class="text-right">
                    <div class="text-sm text-gray-500">Total Score</div>
                    <div class={`text-3xl font-bold ${getScoreColor(result.value.totalScore)}`}>
                      {result.value.totalScore.toFixed(1)}
                    </div>
                  </div>
                </div>
                <div class="mt-3 text-sm text-gray-600">
                  {result.value.verdict === "clean" && "This message appears to be legitimate (score < 2.0)"}
                  {result.value.verdict === "suspicious" && "This message has some spam characteristics (score 2.0 - 5.0)"}
                  {result.value.verdict === "spam" && "This message is likely spam (score >= 5.0)"}
                </div>
              </div>
            );
          })()}

          {/* Score Breakdown */}
          <div class="bg-white rounded-lg shadow border border-gray-200">
            <div class="px-4 py-3 border-b border-gray-200">
              <h3 class="text-sm font-medium text-gray-700">
                Score Breakdown ({filteredRules.length} rules)
              </h3>
            </div>
            <div class="overflow-x-auto">
              <table class="w-full text-sm">
                <thead>
                  <tr class="border-b border-gray-200 bg-gray-50">
                    <th class="text-left py-2 px-4 font-medium text-gray-700 w-20">Score</th>
                    <th class="text-left py-2 px-4 font-medium text-gray-700 w-40">Rule</th>
                    <th class="text-left py-2 px-4 font-medium text-gray-700">Description</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRules.map((rule, index) => (
                    <tr
                      key={index}
                      class={`border-b border-gray-100 ${getScoreBgColor(rule.score)} ${rule.isNotice ? "opacity-60" : ""}`}
                    >
                      <td class={`py-2 px-4 font-mono font-bold ${getScoreColor(rule.score)}`}>
                        {rule.score >= 0 ? "+" : ""}{rule.score.toFixed(1)}
                      </td>
                      <td class="py-2 px-4 font-mono text-gray-800">
                        {rule.ruleName}
                        {rule.isNotice && (
                          <span class="ml-2 text-xs bg-yellow-100 text-yellow-700 px-1 rounded">
                            NOTICE
                          </span>
                        )}
                      </td>
                      <td class="py-2 px-4 text-gray-600 break-words max-w-md">
                        {rule.description}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Stats Cards */}
          <div class="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div class="bg-white rounded-lg p-4 border border-gray-200">
              <div class="text-gray-500 text-xs mb-1">Positive Scores (Spam Indicators)</div>
              <div class="text-2xl font-bold text-red-600">
                {filteredRules.filter(r => r.score > 0).length}
              </div>
              <div class="text-sm text-gray-500">
                +{filteredRules.filter(r => r.score > 0).reduce((sum, r) => sum + r.score, 0).toFixed(1)} points
              </div>
            </div>
            <div class="bg-white rounded-lg p-4 border border-gray-200">
              <div class="text-gray-500 text-xs mb-1">Negative Scores (Ham Indicators)</div>
              <div class="text-2xl font-bold text-green-600">
                {filteredRules.filter(r => r.score < 0).length}
              </div>
              <div class="text-sm text-gray-500">
                {filteredRules.filter(r => r.score < 0).reduce((sum, r) => sum + r.score, 0).toFixed(1)} points
              </div>
            </div>
            <div class="bg-white rounded-lg p-4 border border-gray-200">
              <div class="text-gray-500 text-xs mb-1">Neutral / Info</div>
              <div class="text-2xl font-bold text-gray-600">
                {filteredRules.filter(r => r.score === 0).length}
              </div>
              <div class="text-sm text-gray-500">
                0.0 points
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Reference Section */}
      <details class="mt-6 bg-gray-50 rounded-lg border border-gray-200">
        <summary class="px-4 py-3 cursor-pointer text-sm font-medium text-gray-700 hover:bg-gray-100 rounded-lg">
          SpamAssassin Score Reference
        </summary>
        <div class="px-4 pb-4">
          <div class="text-sm text-gray-600 space-y-2">
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-2">
              <div>
                <h4 class="font-medium text-gray-800 mb-1">Score Thresholds</h4>
                <ul class="space-y-1">
                  <li class="flex items-center gap-2">
                    <span class="w-16 text-green-600 font-mono">&lt; 2.0</span>
                    <span>Clean / Legitimate</span>
                  </li>
                  <li class="flex items-center gap-2">
                    <span class="w-16 text-yellow-600 font-mono">2.0-5.0</span>
                    <span>Suspicious</span>
                  </li>
                  <li class="flex items-center gap-2">
                    <span class="w-16 text-red-600 font-mono">&gt;= 5.0</span>
                    <span>Likely Spam</span>
                  </li>
                </ul>
              </div>
              <div>
                <h4 class="font-medium text-gray-800 mb-1">Score Meanings</h4>
                <ul class="space-y-1">
                  <li class="flex items-center gap-2">
                    <span class="w-16 text-red-600 font-mono">+X.X</span>
                    <span>Indicates spam characteristics</span>
                  </li>
                  <li class="flex items-center gap-2">
                    <span class="w-16 text-green-600 font-mono">-X.X</span>
                    <span>Indicates legitimate email</span>
                  </li>
                  <li class="flex items-center gap-2">
                    <span class="w-16 text-gray-500 font-mono">0.0</span>
                    <span>Informational / No impact</span>
                  </li>
                </ul>
              </div>
            </div>
            <p class="mt-3 text-xs text-gray-500">
              Note: Administrator notices (e.g., blocked DNS queries) typically have 0.0 scores and indicate
              configuration issues rather than spam characteristics.
            </p>
          </div>
        </div>
      </details>

      {/* Default Rules Reference */}
      <details class="mt-4 bg-white rounded-lg border border-gray-200 shadow-sm">
        <summary class="px-4 py-3 cursor-pointer text-sm font-medium text-gray-700 hover:bg-gray-50 rounded-lg">
          Default SpamAssassin Rules Reference ({DEFAULT_RULES.length} rules)
        </summary>
        <div class="px-4 pb-4">
          {/* Search and Filter */}
          <div class="flex flex-wrap gap-3 mb-4 mt-2">
            <input
              type="text"
              value={ruleSearch.value}
              onInput={(e) => ruleSearch.value = (e.target as HTMLInputElement).value}
              placeholder="Search rules..."
              class="flex-1 min-w-48 px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            />
            <select
              value={ruleCategory.value}
              onChange={(e) => ruleCategory.value = (e.target as HTMLSelectElement).value}
              class="px-3 py-2 text-sm border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
            >
              {RULE_CATEGORIES.map((cat) => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>
          </div>

          {/* Rules Table */}
          {(() => {
            const searchLower = ruleSearch.value.toLowerCase();
            const filteredDefaultRules = DEFAULT_RULES.filter((rule) => {
              const matchesSearch = !searchLower ||
                rule.name.toLowerCase().includes(searchLower) ||
                rule.description.toLowerCase().includes(searchLower);
              const matchesCategory = ruleCategory.value === "All" || rule.category === ruleCategory.value;
              return matchesSearch && matchesCategory;
            });

            return (
              <>
                <div class="text-xs text-gray-500 mb-2">
                  Showing {filteredDefaultRules.length} of {DEFAULT_RULES.length} rules
                </div>
                <div class="overflow-x-auto max-h-96 overflow-y-auto border border-gray-200 rounded-lg">
                  <table class="w-full text-sm">
                    <thead class="sticky top-0 bg-gray-50">
                      <tr class="border-b border-gray-200">
                        <th class="text-left py-2 px-3 font-medium text-gray-700 w-20">Score</th>
                        <th class="text-left py-2 px-3 font-medium text-gray-700 w-56">Rule Name</th>
                        <th class="text-left py-2 px-3 font-medium text-gray-700 w-24">Category</th>
                        <th class="text-left py-2 px-3 font-medium text-gray-700">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredDefaultRules.map((rule, index) => (
                        <tr
                          key={index}
                          class={`border-b border-gray-100 ${getScoreBgColor(rule.score)} hover:opacity-80`}
                        >
                          <td class={`py-2 px-3 font-mono font-bold ${getScoreColor(rule.score)}`}>
                            {rule.score >= 0 ? "+" : ""}{rule.score.toFixed(1)}
                          </td>
                          <td class="py-2 px-3 font-mono text-gray-800 text-xs">
                            {rule.name}
                          </td>
                          <td class="py-2 px-3">
                            <span class={`text-xs px-2 py-0.5 rounded-full ${
                              rule.category === "Phishing" ? "bg-purple-100 text-purple-700" :
                              rule.category === "Scam" ? "bg-orange-100 text-orange-700" :
                              rule.category === "Forgery" ? "bg-red-100 text-red-700" :
                              rule.category === "Network" ? "bg-blue-100 text-blue-700" :
                              rule.category === "Auth" ? "bg-green-100 text-green-700" :
                              rule.category === "HTML" ? "bg-pink-100 text-pink-700" :
                              rule.category === "URI" ? "bg-indigo-100 text-indigo-700" :
                              rule.category === "Bayes" ? "bg-cyan-100 text-cyan-700" :
                              rule.category === "Whitelist" ? "bg-emerald-100 text-emerald-700" :
                              "bg-gray-100 text-gray-700"
                            }`}>
                              {rule.category}
                            </span>
                          </td>
                          <td class="py-2 px-3 text-gray-600 text-xs">
                            {rule.description}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <p class="mt-3 text-xs text-gray-500">
                  Source: <a
                    href="https://github.com/apache/spamassassin/tree/trunk/rulesrc/scores"
                    target="_blank"
                    rel="noopener noreferrer"
                    class="text-blue-600 hover:underline"
                  >
                    Apache SpamAssassin GitHub Repository
                  </a>
                </p>
              </>
            );
          })()}
        </div>
      </details>
    </div>
  );
}
