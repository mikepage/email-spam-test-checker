import { Head } from "fresh/runtime";
import { define } from "../utils.ts";
import SpamScoreChecker from "../islands/SpamScoreChecker.tsx";

export default define.page(function SpamScoreCheckerPage() {
  return (
    <div class="min-h-screen bg-[#fafafa]">
      <Head>
        <title>Spam Score Checker</title>
      </Head>
      <div class="px-6 md:px-12 py-8">
        <div class="max-w-6xl mx-auto">
          <h1 class="text-2xl font-normal text-[#111] tracking-tight mb-2">
            Spam Score Checker
          </h1>
          <p class="text-[#666] text-sm mb-8">
            Analyze SpamAssassin reports and get a breakdown of sender spam scores.
          </p>
          <SpamScoreChecker />
        </div>
      </div>
    </div>
  );
});
