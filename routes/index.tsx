import { Head } from "fresh/runtime";
import { define } from "../utils.ts";
import SpamScoreChecker from "../islands/SpamScoreChecker.tsx";

export default define.page(function SpamScoreCheckerPage() {
  return (
    <div class="min-h-screen bg-gray-100">
      <Head>
        <title>Spam Score Checker - Analyze SpamAssassin Reports</title>
      </Head>
      <div class="px-4 py-8">
        <div class="max-w-6xl mx-auto">
          <h1 class="text-3xl font-bold text-gray-800 mb-2">Spam Score Checker</h1>
          <p class="text-gray-600 mb-6">
            Analyze SpamAssassin reports and get a breakdown of sender spam scores.
          </p>
          <SpamScoreChecker />
        </div>
      </div>
    </div>
  );
});
