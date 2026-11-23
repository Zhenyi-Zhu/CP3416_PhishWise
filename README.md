# PhishWise

**Phishing Cue Analysis and Explanation**

PhishWise highlights selected phrases in English email text and explains why a reader might need to check them. It focuses on four types of behavioural cues: time pressure, claimed authority, threatened consequences, and rewards or special offers.

## Quick start

Requires Python 3.10 or later with Tkinter and a graphical desktop.

Run the following command from the project folder:

```powershell
py app.py
```

Select an example, click **Load example**, then click **Analyze email**. You can also paste your own English email text.

## Features

- Paste email text or load one of six synthetic examples.
- Highlight matched phrases using a different colour for each category.
- View the matching rule, a possible influence mechanism, and a suggested verification step.
- Click a finding to locate the phrase in the original text.
- Export findings as JSON.
- Clear outdated results automatically when the input changes.

Category counts show phrase occurrences, not risk scores. Matching a phrase does not establish that an email is phishing, and finding no matches does not mean an email is safe.

## Project files

| File or folder | Purpose |
| --- | --- |
| `app.py` | Tkinter interface, highlighting, and JSON export |
| `analyzer.py` | Phrase-matching rules and explanations |
| `examples.py` | Six synthetic demonstration emails |
| `run_tests.py` | Application test runner and log generation |
| `tests/` | Analyzer and GUI tests |
| `evaluate.py` | Evaluation of message-level cue categories |
| `evaluation/cases.json` | Additional messages, proposed labels, and dataset metadata |
| `evaluation/test_evaluator.py` | Tests for evaluation calculations and dataset validation |
| `evaluation/baseline_linux/` | Original Linux evaluation results |
| `evidence/` | Saved test logs, Windows evaluation results, and example exports |

## Software testing

Run the application tests from the project folder:

```powershell
py run_tests.py
```

The suite contains 29 analyzer tests and 9 GUI tests. It covers phrase matching, input validation, text offsets, result clearing, export, and error handling.

The first Windows run found a Unicode highlighting problem: the interface selected `ct now.` instead of `Act now`. The correction made highlighting and click-to-locate use the analyzer's text offsets directly.

The Windows retest on 20 November 2026 passed all 38 tests. Both the original failure log and the successful retest log are retained in `evidence/`.

GUI tests require a graphical desktop and are skipped when a display is unavailable. A skipped GUI test is not a pass.

The evaluation calculations have five separate tests:

```powershell
py -m unittest discover -s evaluation -p test_evaluator.py -v
```

These five tests are separate from the 38 application tests.

## Additional cue evaluation

Run the evaluation with:

```powershell
py evaluate.py
```

The runner compares the expected and detected cue categories for 24 constructed messages. Each message is checked against four categories, giving 96 message-category decisions. Repeated matches within one category count once for this evaluation.

The messages and proposed labels were created with AI assistance, with access to the existing rules. They are separate from the six built-in examples, but are not an independent benchmark. The labels have not been independently validated. These results describe this selected sample only.

### Results

| Measure | Result |
| --- | ---: |
| Exact category-set agreement | 16/24 (66.7%) |
| Micro precision | 100.0% |
| Micro recall | 66.7% |
| Micro F1 | 80.0% |

| Sample group | Exact category sets |
| --- | ---: |
| Direct wording | 8/8 |
| Alternative wording | 0/8 |
| Ordinary notices with cues | 4/4 |
| No target cues | 4/4 |

Each alternative-wording case had one missing category. For example, “ten minutes left” and “without delay” expressed urgency but did not match the configured rules.

The 100.0% precision result means there were no extra category predictions in this selected sample. It does not mean the tool has 100% phishing detection accuracy.

### Reproducing the results

Each evaluation run creates a new folder under `evidence/` containing:

- `summary.txt`: environment details, metrics, and mismatches.
- `results.csv`: results for each message.
- `results.json`: findings, dataset metadata, and file hashes.

The runner checks the analyzer against the baseline hash recorded in `cases.json`. The rules and dataset used for the original evaluation have been retained.

## Limitations and privacy

The rules cover a small set of English phrases. They can miss unfamiliar wording and cannot reliably interpret complex context.

Legitimate messages can contain the same cues. PhishWise does not authenticate senders, inspect links or attachments, or access an inbox.

Input is processed locally and is not saved automatically. JSON export is optional, but exported findings can contain matched text and surrounding context.

No participant study was conducted. Whether the explanations improve users' decisions or confidence calibration has not been measured.

Future work could broaden phrase coverage, add counterexamples, and evaluate fresh samples with independent label review.

## AI assistance

I used ChatGPT for brainstorming, grammar and formatting improvements, code revision and suggestions for testing. AI also assisted with the synthetic examples and proposed evaluation labels. I ran the application, tests, and evaluation on Windows.
