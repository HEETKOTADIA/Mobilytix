from flask import Flask, render_template, request, redirect, url_for, flash
from pathlib import Path
import os

from modules.ai.ai_indexer import SessionIndexer
from modules.ai.ai_query import AIQueryEngine
from modules.ai.ai_reporter import ForensicReporter

app = Flask(__name__)
app.secret_key = "mobilytix_secret"  # change if needed


# -----------------------------
# Home Page
# -----------------------------
@app.route("/")
def home():
    return render_template("index.html")


# -----------------------------
# Select Session Folder
# -----------------------------
@app.route("/select_session", methods=["POST"])
def select_session():
    folder = request.form.get("session_folder")
    api_key = request.form.get("groq_api_key")

    if not folder or not os.path.isdir(folder):
        flash("Invalid session folder.", "danger")
        return redirect("/")

    if not api_key:
        flash("Groq API key required.", "danger")
        return redirect("/")

    return redirect(url_for("session_menu", session_path=folder, api_key=api_key))


# -----------------------------
# Session Menu
# -----------------------------
@app.route("/session")
def session_menu():
    session_path = request.args.get("session_path")
    api_key = request.args.get("api_key")
    return render_template("indexer.html", session_path=session_path, api_key=api_key)


# -----------------------------
# Index Session
# -----------------------------
@app.route("/index_session")
def index_session():
    session_path = request.args.get("session_path")
    api_key = request.args.get("api_key")

    indexer = SessionIndexer(session_path)
    indexer.index_all()

    flash("Indexing completed successfully!", "success")
    return redirect(url_for("session_menu", session_path=session_path, api_key=api_key))


# -----------------------------
# Query Page
# -----------------------------
@app.route("/query")
def query_page():
    session_path = request.args.get("session_path")
    api_key = request.args.get("api_key")
    return render_template("query.html", session_path=session_path, api_key=api_key)


# -----------------------------
# Run Query
# -----------------------------
@app.route("/ask", methods=["POST"])
def ask():
    question = request.form.get("question")
    session_path = request.form.get("session_path")
    api_key = request.form.get("api_key")

    engine = AIQueryEngine(api_key, session_path)
    answer = engine.query(question)

    return render_template("query.html",
                           session_path=session_path,
                           api_key=api_key,
                           question=question,
                           answer=answer)


# -----------------------------
# Report Page
# -----------------------------
@app.route("/report")
def report_page():
    session_path = request.args.get("session_path")
    api_key = request.args.get("api_key")
    return render_template("report.html", session_path=session_path, api_key=api_key)


# -----------------------------
# Generate Report
# -----------------------------
@app.route("/generate_report", methods=["POST"])
def generate_report():
    session_path = request.form.get("session_path")
    api_key = request.form.get("api_key")

    reporter = ForensicReporter(api_key, session_path)
    report_text = reporter.generate_report()

    return render_template("report.html",
                           session_path=session_path,
                           api_key=api_key,
                           report=report_text)


if __name__ == "__main__":
    app.run(debug=True, port=8080)
