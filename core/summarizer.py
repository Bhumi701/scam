import re
import logging
from typing import List
from core.ensemble import get_bart_pipeline

# Configure logger
logger = logging.getLogger("scam_detector.summarizer")
logging.basicConfig(level=logging.INFO)


class Summarizer:
    def __init__(self):
        pass

    def generate_summary(self, transcript: str) -> str:
        """
        Generates a concise 2-line summary of the call transcript.
        Reuses the BART zero-shot classification model from core/ensemble.py
        to perform high-performance extractive sentence selection without
        requiring loading duplicate generative weights onto CPU.
        """
        cleaned_transcript = transcript.strip()
        if not cleaned_transcript:
            return "No transcript content available to summarize."

        # Split transcript into sentences supporting English (. ! ?) and Hindi (। |) delimiters
        sentences = re.split(r"(?<=[.!?।|])\s+", cleaned_transcript)
        # Clean sentences and remove empty/unusually short elements
        sentences = [s.strip() for s in sentences if len(s.strip()) > 5]

        if not sentences:
            return "Transcript is too short or lacks structure to extract a summary."

        # If transcript contains 1 or 2 sentences, return them directly
        if len(sentences) <= 2:
            return " ".join(sentences)

        logger.info(f"Extracting 2-line summary from {len(sentences)} sentences using zero-shot ranking...")
        bart = get_bart_pipeline()

        # Score sentences based on their informative content and threat details
        candidate_labels = ["scam claim, pressure, request, or threat statement", "insignificant filler talk"]
        
        sentence_scores = []
        for index, sentence in enumerate(sentences):
            try:
                # We classify each sentence individually to locate the critical conversational content
                res = bart(sentence, candidate_labels=candidate_labels)
                label_scores = dict(zip(res["labels"], res["scores"]))
                score = float(label_scores.get("scam claim, pressure, request, or threat statement", 0.0))
                sentence_scores.append((index, sentence, score))
            except Exception as e:
                logger.warning(f"Failed to score sentence index {index}: {e}")
                # Fallback to neutral score
                sentence_scores.append((index, sentence, 0.5))

        # Sort sentences by risk/relevance score descending
        ranked_sentences = sorted(sentence_scores, key=lambda x: x[2], reverse=True)

        # Select top 2 most representative sentences
        top_two = ranked_sentences[:2]

        # Re-sort chronologically based on their original position in the call flow
        top_two_chronological = sorted(top_two, key=lambda x: x[0])

        # Extract sentence texts
        extracted_lines = [item[1] for item in top_two_chronological]

        # Join lines into a cohesive 2-line output
        summary_output = " ".join(extracted_lines)
        logger.info("2-line summary successfully extracted.")
        return summary_output