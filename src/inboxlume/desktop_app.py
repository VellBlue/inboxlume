from __future__ import annotations

import json
import sys
import webbrowser
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from PySide6.QtCore import (
        QProcess,
        QProcessEnvironment,
        QThread,
        QTime,
        QTimer,
        Qt,
        Signal,
    )
    from PySide6.QtGui import QCloseEvent, QColor, QFont, QPalette
    from PySide6.QtWidgets import (
        QApplication,
        QButtonGroup,
        QCheckBox,
        QComboBox,
        QDialog,
        QDialogButtonBox,
        QFileDialog,
        QFormLayout,
        QFrame,
        QGridLayout,
        QHBoxLayout,
        QLabel,
        QListWidget,
        QListWidgetItem,
        QLineEdit,
        QMainWindow,
        QMessageBox,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QScrollArea,
        QSpinBox,
        QStyleFactory,
        QTextEdit,
        QTimeEdit,
        QVBoxLayout,
        QWidget,
    )
except ModuleNotFoundError as exc:  # pragma: no cover - dipendenza opzionale
    raise SystemExit(
        "La GUI multipiattaforma richiede PySide6. "
        "Installa il progetto con: pip install -e '.[desktop]'"
    ) from exc

from .models import ProviderKind
from .auth import AuthenticationService, ConnectionState
from .credential_store import CredentialStoreError
from .duration_estimator import EstimateConfidence, ScanDurationEstimate
from .i18n import UiLanguage, ui_text
from .local_models import (
    MODEL_CATALOG,
    LocalModelProfile,
    detect_hardware,
    inspect_model_availability,
    model_spec,
    recommended_available_profile,
    scan_profile_for_model,
)
from .native_scheduler import (
    NativeScheduleBackend,
    ScheduleRequest,
    ScheduleStatus,
    SchedulerError,
    native_scheduler,
)
from .process_launch import (
    desktop_worker_launch,
    scheduled_worker_launch,
    terminate_process_tree,
)
from .runtime import (
    calibration_answer_counts,
    default_runtime_config_path,
    local_lumegraph_summary,
    local_obsolescence_proof_summary,
    local_scan_duration_estimate,
    local_safety_governor_report,
    local_threat_assessment_summary,
    local_temporal_drift_report,
    local_versioned_safety_backtest,
    record_local_scan_timing,
    state_database_path,
)
from .safety_backtest import BacktestTrend
from .safety_governor import (
    DEFAULT_MINIMUM_CONCLUSIVE_REVIEWS,
    DIRECT_TRASH_MINIMUM_CONCLUSIVE_REVIEWS,
    GovernorStatus,
    operational_governor_available,
    operational_quarantine_gate,
)
from .temporal_drift import TemporalDriftReport, TemporalDriftStatus
from .threat_signals import ThreatSemanticMode
from .settings import (
    AccountSettings,
    ApplicationSettings,
    MessageDestination,
    RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_KEEP_ANSWERS,
    RECOMMENDED_INITIAL_QUIZ_ANSWERS,
    ScanOrder,
    ScheduleFrequency,
    ScheduleSettings,
    SettingsStore,
    scoped_account_removal,
    scoped_account_replacement,
)


APP_VERSION = "0.5.0-dev"


STYLE_SHEET = """
QMainWindow, QWidget#appRoot {
    background: #F4F7F6;
    color: #17231F;
}
QDialog {
    background: #F4F7F6;
    color: #17231F;
}
QWidget {
    font-family: "Inter", "SF Pro Text", "Segoe UI", sans-serif;
    font-size: 14px;
}
QFrame#sidebar {
    background: #11251F;
    border: none;
}
QFrame#languageSwitch {
    background: #0B1C17;
    border: 1px solid #315147;
    border-radius: 9px;
}
QPushButton#languageOption {
    min-height: 30px;
    color: #B9CBC4;
    background: transparent;
    border: none;
    border-radius: 7px;
    padding: 4px 8px;
    font-size: 12px;
    font-weight: 650;
}
QPushButton#languageOption:hover {
    color: #FFFFFF;
    background: #1B352D;
}
QPushButton#languageOption:checked {
    color: #0C271E;
    background: #55D7A6;
    font-weight: 760;
}
QLabel#brandMark {
    background: #2BC28A;
    color: #0D211A;
    border-radius: 12px;
    font-size: 18px;
    font-weight: 800;
}
QLabel#brandTitle {
    color: #F4FBF8;
    font-size: 19px;
    font-weight: 750;
}
QLabel#brandCaption, QLabel#sidebarFootnote {
    color: #98AEA6;
    font-size: 12px;
}
QListWidget#accountList {
    background: transparent;
    border: none;
    outline: none;
    color: #C8D6D1;
    padding: 0;
}
QListWidget#accountList::item {
    border-radius: 9px;
    padding: 12px 13px;
    margin: 3px 0;
}
QListWidget#accountList::item:selected {
    background: #1E3B32;
    color: #FFFFFF;
}
QLabel#eyebrow {
    color: #20815F;
    font-size: 12px;
    font-weight: 700;
}
QLabel#pageTitle {
    color: #13201C;
    font-size: 30px;
    font-weight: 760;
}
QLabel#pageDescription, QLabel#fieldHint, QLabel#statusText {
    color: #62726C;
}
QLabel#statusPill {
    color: #176B4E;
    background: #DDF3EA;
    border-radius: 12px;
    padding: 5px 10px;
    font-size: 12px;
    font-weight: 650;
}
QLabel#statusPill[outcomeState="active"] {
    color: #315C85;
    background: #E4EFF9;
}
QLabel#statusPill[outcomeState="warning"] {
    color: #855A16;
    background: #FFF0CF;
}
QLabel#statusPill[outcomeState="changed"] {
    color: #176B4E;
    background: #CFEBDD;
}
QFrame#privacyBanner {
    background: #173F33;
    border: 1px solid #245C4B;
    border-radius: 13px;
}
QLabel#privacyTitle {
    color: #8DE7C3;
    font-size: 12px;
    font-weight: 760;
}
QLabel#privacyText {
    color: #F1FAF6;
    font-size: 14px;
}
QFrame#card {
    background: #FFFFFF;
    border: 1px solid #DDE7E3;
    border-radius: 14px;
}
QFrame#scanCard {
    background: #E8F7F1;
    border: 2px solid #40B98B;
    border-radius: 16px;
}
QFrame#scanCard QLabel#cardTitle {
    color: #0D4F39;
    font-size: 20px;
    font-weight: 780;
}
QLabel#cardTitle {
    color: #182720;
    font-size: 17px;
    font-weight: 720;
}
QLabel#fieldLabel {
    color: #25352F;
    font-weight: 650;
}
QLineEdit, QTextEdit, QSpinBox, QComboBox, QTimeEdit {
    min-height: 38px;
    color: #17231F;
    background: #F9FBFA;
    border: 1px solid #CDD9D4;
    border-radius: 8px;
    padding: 0 10px;
    selection-background-color: #2AB780;
    selection-color: #FFFFFF;
}
QTextEdit { padding: 8px; }
QLineEdit:focus, QTextEdit:focus, QSpinBox:focus, QComboBox:focus, QTimeEdit:focus {
    border: 2px solid #2AB780;
}
QLineEdit:disabled, QTextEdit:disabled, QSpinBox:disabled,
QComboBox:disabled, QTimeEdit:disabled {
    color: #65736E;
    background: #EEF2F0;
    border-color: #D6DFDB;
}
QComboBox QAbstractItemView {
    color: #17231F;
    background: #FFFFFF;
    border: 1px solid #CDD9D4;
    outline: none;
    padding: 4px;
    selection-color: #0C271E;
    selection-background-color: #55D7A6;
}
QRadioButton {
    spacing: 9px;
    color: #273731;
    padding: 3px 0;
}
QRadioButton::indicator {
    width: 17px;
    height: 17px;
}
QCheckBox {
    spacing: 10px;
    color: #273731;
    padding: 4px 0;
}
QCheckBox::indicator {
    width: 18px;
    height: 18px;
    background: #FFFFFF;
    border: 2px solid #789188;
    border-radius: 4px;
}
QCheckBox::indicator:hover {
    border-color: #19875F;
}
QCheckBox::indicator:checked {
    background: #19875F;
    border-color: #126A4A;
}
QCheckBox::indicator:disabled {
    background: #E8EEEB;
    border-color: #B9C7C2;
}
QLabel#warningBox {
    color: #754512;
    background: #FFF2DC;
    border: 1px solid #F0D19D;
    border-radius: 9px;
    padding: 10px 12px;
}
QLabel#safeBox {
    color: #24634F;
    background: #E9F7F1;
    border: 1px solid #BFE5D6;
    border-radius: 9px;
    padding: 10px 12px;
}
QLabel#connectionReady {
    color: #176B4E;
    background: #DDF3EA;
    border-radius: 9px;
    padding: 9px 11px;
    font-weight: 650;
}
QLabel#connectionPartial {
    color: #765016;
    background: #FFF2DC;
    border-radius: 9px;
    padding: 9px 11px;
    font-weight: 650;
}
QLabel#connectionOff {
    color: #5F6D68;
    background: #EEF2F0;
    border-radius: 9px;
    padding: 9px 11px;
    font-weight: 650;
}
QPushButton#primaryButton {
    color: #FFFFFF;
    background: #19875F;
    border: none;
    border-radius: 9px;
    padding: 10px 18px;
    font-weight: 700;
}
QPushButton#primaryButton:hover { background: #146E4E; }
QPushButton#primaryButton:pressed { background: #105A40; }
QPushButton#scanPrimaryButton {
    min-height: 52px;
    color: #FFFFFF;
    background: #0E7551;
    border: 2px solid #0A6244;
    border-radius: 11px;
    padding: 11px 24px;
    font-size: 16px;
    font-weight: 780;
}
QPushButton#scanPrimaryButton:hover {
    background: #0A6244;
    border-color: #084E37;
}
QPushButton#scanPrimaryButton:pressed { background: #063F2D; }
QPushButton#scanPrimaryButton:disabled {
    color: #6F817A;
    background: #D9E5E0;
    border-color: #C5D4CE;
}
QPushButton#secondaryButton {
    color: #2A3B35;
    background: #FFFFFF;
    border: 1px solid #CBD8D3;
    border-radius: 9px;
    padding: 9px 16px;
    font-weight: 650;
}
QPushButton#secondaryButton:hover { background: #F0F5F3; }
QPushButton:disabled {
    color: #8B9792;
    background: #E8EEEB;
    border-color: #D9E1DE;
}
QProgressBar {
    min-height: 18px;
    border: 1px solid #CDD9D4;
    border-radius: 8px;
    background: #F3F7F5;
    text-align: center;
    color: #294039;
}
QProgressBar::chunk { background: #2AB780; border-radius: 7px; }
QScrollArea#settingsScroll,
QWidget#settingsViewport,
QWidget#settingsContent {
    border: none;
    background: #F4F7F6;
}
QScrollBar:vertical {
    width: 10px;
    margin: 0;
    border: none;
    background: #E7EEEB;
}
QScrollBar::handle:vertical {
    min-height: 34px;
    border-radius: 5px;
    background: #AABAB4;
}
QScrollBar::handle:vertical:hover { background: #82958E; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {
    background: transparent;
}
"""


def configure_application_appearance(app: QApplication) -> None:
    """Install one deterministic light palette across supported platforms."""
    fusion = QStyleFactory.create("Fusion")
    if fusion is not None:
        app.setStyle(fusion)

    palette = QPalette()
    for role, color in (
        (QPalette.ColorRole.Window, "#F4F7F6"),
        (QPalette.ColorRole.WindowText, "#17231F"),
        (QPalette.ColorRole.Base, "#FFFFFF"),
        (QPalette.ColorRole.AlternateBase, "#EEF3F1"),
        (QPalette.ColorRole.ToolTipBase, "#FFFFFF"),
        (QPalette.ColorRole.ToolTipText, "#17231F"),
        (QPalette.ColorRole.Text, "#17231F"),
        (QPalette.ColorRole.Button, "#FFFFFF"),
        (QPalette.ColorRole.ButtonText, "#2A3B35"),
        (QPalette.ColorRole.Highlight, "#55D7A6"),
        (QPalette.ColorRole.HighlightedText, "#0C271E"),
        (QPalette.ColorRole.PlaceholderText, "#788680"),
    ):
        palette.setColor(role, QColor(color))
    for role, color in (
        (QPalette.ColorRole.WindowText, "#65736E"),
        (QPalette.ColorRole.Text, "#65736E"),
        (QPalette.ColorRole.ButtonText, "#65736E"),
        (QPalette.ColorRole.Base, "#EEF2F0"),
        (QPalette.ColorRole.Button, "#E8EEEB"),
    ):
        palette.setColor(QPalette.ColorGroup.Disabled, role, QColor(color))
    app.setPalette(palette)
    app.setStyleSheet(STYLE_SHEET)


class SettingCard(QFrame):
    def __init__(self, title: str, description: str) -> None:
        super().__init__()
        self.setObjectName("card")
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(22, 20, 22, 20)
        self.layout.setSpacing(13)

        title_label = QLabel(title)
        title_label.setObjectName("cardTitle")
        description_label = QLabel(description)
        description_label.setObjectName("fieldHint")
        description_label.setWordWrap(True)
        self.layout.addWidget(title_label)
        self.layout.addWidget(description_label)

    def add_field(self, label: str, hint: str, control: QWidget) -> None:
        row = QHBoxLayout()
        row.setSpacing(20)
        text_column = QVBoxLayout()
        text_column.setSpacing(3)
        field_label = QLabel(label)
        field_label.setObjectName("fieldLabel")
        field_hint = QLabel(hint)
        field_hint.setObjectName("fieldHint")
        field_hint.setWordWrap(True)
        text_column.addWidget(field_label)
        text_column.addWidget(field_hint)
        row.addLayout(text_column, 1)
        control.setMinimumWidth(210)
        control.setMaximumWidth(300)
        row.addWidget(control, 0, Qt.AlignmentFlag.AlignVCenter)
        self.layout.addLayout(row)


class BackgroundTask(QThread):
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, action: Callable[[], object]) -> None:
        super().__init__()
        self.action = action

    def run(self) -> None:
        try:
            self.succeeded.emit(self.action())
        except Exception as exc:
            self.failed.emit(str(exc) or exc.__class__.__name__)


class YahooCredentialsDialog(QDialog):
    GUIDE_URL = "https://help.yahoo.com/kb/account/confirm-delete-password-sln15241.html"

    def __init__(self, language: UiLanguage, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.language = language
        self._ = lambda message, **values: ui_text(language, message, **values)
        self.setWindowTitle(self._("Connect Yahoo"))
        self.setMinimumWidth(520)
        layout = QVBoxLayout(self)
        title = QLabel(self._("Yahoo app password"))
        title.setObjectName("cardTitle")
        explanation = QLabel(self._(
            "Yahoo requires a dedicated app password. Do not enter your main account password."
        ))
        explanation.setWordWrap(True)
        layout.addWidget(title)
        layout.addWidget(explanation)
        guide = QPushButton(self._("Open Yahoo's app-password guide"))
        guide.setObjectName("secondaryButton")
        guide.clicked.connect(lambda: webbrowser.open(self.GUIDE_URL, new=1))
        layout.addWidget(guide)

        form = QFormLayout()
        self.email = QLineEdit()
        self.email.setPlaceholderText(self._("person@example.com"))
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.EchoMode.Password)
        self.password.setPlaceholderText(self._("App password"))
        form.addRow(self._("Yahoo address"), self.email)
        form.addRow(self._("App password"), self.password)
        layout.addLayout(form)

        privacy = QLabel(self._(
            "The password is stored in the operating system's credential manager, never in preferences or logs."
        ))
        privacy.setObjectName("safeBox")
        privacy.setWordWrap(True)
        layout.addWidget(privacy)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Save
        )
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _validate_and_accept(self) -> None:
        if "@" not in self.email.text() or len(self.password.text()) < 8:
            QMessageBox.warning(
                self,
                self._("Incomplete details"),
                self._("Enter the Yahoo address and its app password."),
            )
            return
        self.accept()

    def _(self, message: str, **values: object) -> str:
        return ui_text(self.language, message, **values)


class AddAccountDialog(QDialog):
    def __init__(self, language: UiLanguage, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.language = language
        self._ = lambda message, **values: ui_text(language, message, **values)
        self.setWindowTitle(self._("Add account"))
        self.setMinimumWidth(430)
        layout = QVBoxLayout(self)
        intro = QLabel(self._(
            "Every account has separate credentials, preferences, history, and quiz data."
        ))
        intro.setWordWrap(True)
        layout.addWidget(intro)
        form = QFormLayout()
        self.provider = QComboBox()
        self.provider.addItem("Gmail", ProviderKind.GMAIL)
        self.provider.addItem("Yahoo", ProviderKind.YAHOO)
        self.name = QLineEdit()
        self.name.setPlaceholderText(self._("For example, Work Gmail"))
        form.addRow("Provider", self.provider)
        form.addRow(self._("Name in InboxLume"), self.name)
        layout.addLayout(form)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Cancel
            | QDialogButtonBox.StandardButton.Save
        )
        buttons.accepted.connect(self._validate_and_accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

    def _validate_and_accept(self) -> None:
        if not self.name.text().strip():
            QMessageBox.warning(
                self, self._("Missing name"), self._("Enter a name for this account.")
            )
            return
        self.accept()

    def _(self, message: str, **values: object) -> str:
        return ui_text(self.language, message, **values)


class QuizDialog(QDialog):
    answer_selected = Signal(str)
    stop_requested = Signal()

    def __init__(
        self,
        language: UiLanguage,
        parent: QWidget | None = None,
        *,
        review_mode: bool = False,
    ) -> None:
        super().__init__(parent)
        self.language = language
        self.review_mode = review_mode
        self._ = lambda message, **values: ui_text(language, message, **values)
        self.running = True
        self.setWindowTitle(self._(
            "Review filter candidates" if review_mode else "Local calibration"
        ))
        self.setMinimumSize(720, 590)
        layout = QVBoxLayout(self)
        self.position = QLabel(self._("Preparing the quiz…"))
        self.position.setObjectName("eyebrow")
        self.subject = QLabel()
        self.subject.setObjectName("cardTitle")
        self.subject.setWordWrap(True)
        self.metadata = QLabel()
        self.metadata.setObjectName("fieldHint")
        self.metadata.setWordWrap(True)
        self.preview = QTextEdit()
        self.preview.setReadOnly(True)
        self.preview.setAccessibleName(self._("Local message preview"))
        layout.addWidget(self.position)
        layout.addWidget(self.subject)
        layout.addWidget(self.metadata)
        layout.addWidget(self.preview, 1)
        privacy = QLabel(self._(
            "This preview exists only in device memory and is not stored in the database. The quiz never changes the mailbox."
        ))
        privacy.setObjectName("safeBox")
        privacy.setWordWrap(True)
        layout.addWidget(privacy)
        buttons = QHBoxLayout()
        self.keep = QPushButton(self._("Keep"))
        self.keep.setObjectName("secondaryButton")
        self.discard = QPushButton(self._("Don't keep"))
        self.discard.setObjectName("primaryButton")
        self.unsure = QPushButton(self._("Not sure"))
        self.unsure.setObjectName("secondaryButton")
        for button, value in (
            (self.keep, "keep"),
            (self.discard, "dont_keep"),
            (self.unsure, "unsure"),
        ):
            button.clicked.connect(
                lambda checked=False, answer=value: self._answer(answer)
            )
            buttons.addWidget(button)
        layout.addLayout(buttons)

    def _set_answer_buttons(self, enabled: bool) -> None:
        for button in (self.keep, self.discard, self.unsure):
            button.setEnabled(enabled)

    def _answer(self, answer: str) -> None:
        self._set_answer_buttons(False)
        self.answer_selected.emit(answer)

    def show_candidate(self, event: dict[str, Any]) -> None:
        self.position.setText(self._(
            "QUESTION {position} OF {total}",
            position=int(event.get("position", 0)),
            total=int(event.get("total", 0)),
        ))
        self.subject.setText(str(event.get("subject") or self._("(no subject)")))
        sender = str(event.get("sender") or self._("Sender unavailable"))
        received = str(event.get("received_at") or "")
        category = str(event.get("category") or self._("uncertain"))
        metadata_format = (
            "Filter candidate · {sender} · {received} · Category: {category}"
            if event.get("review_kind") == "quarantine_proposal"
            else "{sender} · {received} · Category: {category}"
        )
        self.metadata.setText(self._(
            metadata_format,
            sender=sender,
            received=received,
            category=category,
        ))
        self.preview.setPlainText(str(event.get("preview") or self._("(empty body)")))
        self._set_answer_buttons(True)
        if not self.isVisible():
            self.show()
            self.raise_()
            self.activateWindow()

    def show_summary(self, event: dict[str, Any]) -> None:
        self.running = False
        self.position.setText(self._(
            "FILTER REVIEW COMPLETE"
            if self.review_mode
            else "CALIBRATION COMPLETE"
        ))
        self.subject.setText(self._(
            "{count} filter candidates reviewed locally"
            if self.review_mode
            else "{count} new answers saved locally",
            count=int(event.get("presented", 0)),
        ))
        self.metadata.setText(self._(
            "Keep: {keep} · Don't keep: {discard} · Not sure: {unsure}",
            keep=int(event.get("keep", 0)),
            discard=int(event.get("dont_keep", 0)),
            unsure=int(event.get("unsure", 0)),
        ))
        self.preview.setPlainText(self._(
            "The message text shown during the review was not saved. You can close this window."
            if self.review_mode
            else "The message text shown during the quiz was not saved. You can close this window."
        ))
        self._set_answer_buttons(False)

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self.running:
            self.stop_requested.emit()
        event.accept()

    def _(self, message: str, **values: object) -> str:
        return ui_text(self.language, message, **values)


class SettingsWindow(QMainWindow):
    settings_saved = Signal(str)

    def __init__(
        self,
        store: SettingsStore | None = None,
        auth_service: AuthenticationService | None = None,
        schedule_backend: NativeScheduleBackend | None = None,
    ) -> None:
        super().__init__()
        application = QApplication.instance()
        if application is not None:
            configure_application_appearance(application)
        self.store = store or SettingsStore()
        self.settings = self.store.load()
        # A per-instance callable avoids a PySide/Shiboken name-resolution edge
        # case for a one-character method name on QMainWindow.
        self._ = lambda message, **values: ui_text(
            self.settings.language, message, **values
        )
        self.hardware = detect_hardware()
        self.model_availability = inspect_model_availability(self.hardware)
        self.recommended_model = recommended_available_profile(
            self.model_availability
        )
        self.current_account_id: str | None = None
        self.dirty = False
        self._tasks: set[BackgroundTask] = set()
        self._process: QProcess | None = None
        self._process_buffer = ""
        self._operation: str | None = None
        self._terminal_event_received = False
        self._quiz_dialog: QuizDialog | None = None
        self._calibration_totals: dict[str, int] = {}
        self._calibration_ready: dict[str, bool] = {}
        self._connection_state = ConnectionState.NOT_CONFIGURED
        self._connection_read_access = False
        self._governor_operational_available = False
        self._governor_quarantine_ready = False
        self._governor_trash_ready = False
        self._schedule_busy = False
        self._estimate_busy = False
        self._native_schedule_installed = False
        self.auth_error: str | None = None
        self.scheduler_error: str | None = None
        self.project_root = Path(__file__).resolve().parents[2]
        self.config_path = default_runtime_config_path(self.project_root)
        if auth_service is not None:
            self.auth_service = auth_service
        else:
            try:
                self.auth_service = AuthenticationService(self.config_path)
            except CredentialStoreError as exc:
                self.auth_service = None
                self.auth_error = str(exc)
        if schedule_backend is not None:
            self.schedule_backend = schedule_backend
        else:
            try:
                self.schedule_backend = native_scheduler(self.store.path)
            except SchedulerError as exc:
                self.schedule_backend = None
                self.scheduler_error = str(exc)

        self.setWindowTitle(f"InboxLume — {self._('Preferences')}")
        self.setMinimumSize(960, 650)
        self.resize(1120, 760)
        root = QWidget()
        root.setObjectName("appRoot")
        self.setCentralWidget(root)
        shell = QHBoxLayout(root)
        shell.setContentsMargins(0, 0, 0, 0)
        shell.setSpacing(0)
        shell.addWidget(self._build_sidebar())
        shell.addWidget(self._build_content(), 1)

        self._connect_signals()
        self.account_list.setCurrentRow(0)
        if self.current_account_id is None:
            self._account_changed(0)

    def _(self, message: str, **values: object) -> str:
        return ui_text(self.settings.language, message, **values)

    def _build_sidebar(self) -> QWidget:
        sidebar = QFrame()
        sidebar.setObjectName("sidebar")
        sidebar.setFixedWidth(248)
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(22, 26, 22, 22)
        layout.setSpacing(18)

        brand = QHBoxLayout()
        mark = QLabel("IL")
        mark.setObjectName("brandMark")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        mark.setFixedSize(48, 48)
        brand_text = QVBoxLayout()
        brand_text.setSpacing(1)
        title = QLabel("InboxLume")
        title.setObjectName("brandTitle")
        caption = QLabel("Local email care")
        caption.setObjectName("brandCaption")
        brand_text.addWidget(title)
        brand_text.addWidget(caption)
        brand.addWidget(mark)
        brand.addSpacing(9)
        brand.addLayout(brand_text)
        layout.addLayout(brand)

        account_caption = QLabel(self._("Accounts").upper())
        account_caption.setObjectName("brandCaption")
        layout.addWidget(account_caption)

        self.account_list = QListWidget()
        self.account_list.setObjectName("accountList")
        self.account_list.setSpacing(2)
        self.account_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self._populate_account_list()
        layout.addWidget(self.account_list)
        account_buttons = QVBoxLayout()
        self.add_account_button = QPushButton(self._("+ Add"))
        self.add_account_button.setObjectName("secondaryButton")
        self.remove_account_button = QPushButton(self._("Remove"))
        self.remove_account_button.setObjectName("secondaryButton")
        account_buttons.addWidget(self.add_account_button)
        account_buttons.addWidget(self.remove_account_button)
        layout.addLayout(account_buttons)

        language_label = QLabel(self._("Language").upper())
        language_label.setObjectName("brandCaption")
        layout.addWidget(language_label)
        language_switch = QFrame()
        language_switch.setObjectName("languageSwitch")
        language_layout = QHBoxLayout(language_switch)
        language_layout.setContentsMargins(3, 3, 3, 3)
        language_layout.setSpacing(3)
        self.language_group = QButtonGroup(self)
        self.language_group.setExclusive(True)
        self.english_language_button = QPushButton("English")
        self.italian_language_button = QPushButton("Italiano")
        for button, language in (
            (self.english_language_button, UiLanguage.ENGLISH),
            (self.italian_language_button, UiLanguage.ITALIAN),
        ):
            button.setObjectName("languageOption")
            button.setCheckable(True)
            button.setChecked(self.settings.language is language)
            button.setAccessibleName(self._("Interface language"))
            self.language_group.addButton(button)
            language_layout.addWidget(button, 1)
        layout.addWidget(language_switch)
        layout.addStretch(1)

        local_badge = QLabel(f"●  {self._('Local AI · one-shot runs')}")
        local_badge.setObjectName("sidebarFootnote")
        local_badge.setWordWrap(True)
        layout.addWidget(local_badge)
        version = QLabel(self._("Cross-platform preview · {version}", version=APP_VERSION))
        version.setObjectName("sidebarFootnote")
        version.setWordWrap(True)
        layout.addWidget(version)
        return sidebar

    def _populate_account_list(self, selected_id: str | None = None) -> None:
        self.account_list.blockSignals(True)
        self.account_list.clear()
        selected_row = 0
        for row, account in enumerate(self.settings.accounts):
            provider_name = "Gmail" if account.provider is ProviderKind.GMAIL else "Yahoo"
            label = account.display_name or provider_name
            item = QListWidgetItem(f"  {label}\n  {provider_name}")
            item.setData(Qt.ItemDataRole.UserRole, account.account_id)
            self.account_list.addItem(item)
            if account.account_id == selected_id:
                selected_row = row
        self.account_list.blockSignals(False)
        if self.account_list.count():
            self.account_list.setCurrentRow(selected_row)

    def _build_content(self) -> QWidget:
        container = QWidget()
        outer = QVBoxLayout(container)
        outer.setContentsMargins(34, 28, 34, 24)
        outer.setSpacing(18)

        header = QHBoxLayout()
        header_text = QVBoxLayout()
        header_text.setSpacing(4)
        eyebrow = QLabel(self._("Account preferences").upper())
        eyebrow.setObjectName("eyebrow")
        self.page_title = QLabel(self._("Gmail rules"))
        self.page_title.setObjectName("pageTitle")
        self.page_description = QLabel(self._(
            "Choose which messages may be analysed. Changes stay on this device."
        ))
        self.page_description.setObjectName("pageDescription")
        self.page_description.setWordWrap(True)
        header_text.addWidget(eyebrow)
        header_text.addWidget(self.page_title)
        header_text.addWidget(self.page_description)
        header.addLayout(header_text, 1)
        self.status_pill = QLabel(self._("No email changed"))
        self.status_pill.setObjectName("statusPill")
        self.status_pill.setProperty("outcomeState", "safe")
        self.status_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
        header.addWidget(self.status_pill, 0, Qt.AlignmentFlag.AlignTop)
        outer.addLayout(header)

        privacy = QFrame()
        privacy.setObjectName("privacyBanner")
        privacy_layout = QVBoxLayout(privacy)
        privacy_layout.setContentsMargins(18, 15, 18, 15)
        privacy_layout.setSpacing(4)
        privacy_title = QLabel(self._("Local by design").upper())
        privacy_title.setObjectName("privacyTitle")
        privacy_text = QLabel(self._(
            "The model and preference learning run on your device. Email content is never sent to external AI services."
        ))
        privacy_text.setObjectName("privacyText")
        privacy_text.setWordWrap(True)
        privacy_layout.addWidget(privacy_title)
        privacy_layout.addWidget(privacy_text)
        outer.addWidget(privacy)

        scroll = QScrollArea()
        scroll.setObjectName("settingsScroll")
        scroll.viewport().setObjectName("settingsViewport")
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_content = QWidget()
        scroll_content.setObjectName("settingsContent")
        cards = QVBoxLayout(scroll_content)
        self.settings_cards_layout = cards
        cards.setContentsMargins(0, 0, 8, 0)
        cards.setSpacing(16)

        connection = SettingCard(
            self._("Account connection"),
            self._("Credentials stay in the operating system's protected credential store. The test lists at most one Inbox ID and never reads message bodies."),
        )
        connection.setObjectName("connectionCard")
        self.account_display_name = QLineEdit()
        self.account_display_name.setMaxLength(80)
        self.account_display_name.setPlaceholderText(self._("For example, Work Gmail"))
        self.account_display_name.setAccessibleName(self._("Name in InboxLume"))
        connection.add_field(
            self._("Name in InboxLume"),
            self._("Local label shown only in InboxLume. It does not change the email address or account."),
            self.account_display_name,
        )
        self.connection_status = QLabel(self._("Checking local configuration…"))
        self.connection_status.setWordWrap(True)
        self.connection_status.setMinimumHeight(38)
        connection.layout.addWidget(self.connection_status)
        connection_buttons = QGridLayout()
        connection_buttons.setHorizontalSpacing(10)
        connection_buttons.setVerticalSpacing(8)
        self.connect_button = QPushButton(self._("Connect account"))
        self.connect_button.setObjectName("primaryButton")
        self.action_permission_button = QPushButton(self._("Authorise Quarantine/Trash"))
        self.action_permission_button.setObjectName("secondaryButton")
        self.test_connection_button = QPushButton(self._("Test connection"))
        self.test_connection_button.setObjectName("secondaryButton")
        self.disconnect_button = QPushButton(self._("Disconnect"))
        self.disconnect_button.setObjectName("secondaryButton")
        connection_buttons.addWidget(self.connect_button, 0, 0)
        connection_buttons.addWidget(self.action_permission_button, 0, 1)
        connection_buttons.addWidget(self.test_connection_button, 1, 0)
        connection_buttons.addWidget(self.disconnect_button, 1, 1)
        connection_buttons.setColumnStretch(2, 1)
        connection.layout.addLayout(connection_buttons)
        self.connection_explanation = QLabel()
        self.connection_explanation.setObjectName("fieldHint")
        self.connection_explanation.setWordWrap(True)
        connection.layout.addWidget(self.connection_explanation)
        cards.addWidget(connection)

        local_model = SettingCard(
            self._("Local AI model"),
            self._("Choose a controlled profile. InboxLume checks runtimes and caches without loading or downloading a model."),
        )
        local_model.setObjectName("modelCard")
        self.model_profile = QComboBox()
        self.model_profile.setAccessibleName(self._("Model profile"))
        for profile, spec in MODEL_CATALOG.items():
            self.model_profile.addItem(self._(spec.display_name), profile)
        local_model.add_field(
            self._("Model profile"),
            self._("Gemma 26B is recommended. Smaller models use more conservative limits."),
            self.model_profile,
        )
        self.model_status = QLabel(self._("Checking local runtimes…"))
        self.model_status.setWordWrap(True)
        local_model.layout.addWidget(self.model_status)
        memory = (
            f"{self.hardware.total_memory_gib:g} GB RAM"
            if self.hardware.total_memory_gib is not None
            else self._("RAM not detected")
        )
        self.hardware_status = QLabel(self._(
            "Detected system: {system} {machine} · {memory}. No model benchmark was run.",
            system=self.hardware.system_name,
            machine=self.hardware.machine,
            memory=memory,
        ))
        self.hardware_status.setObjectName("fieldHint")
        self.hardware_status.setWordWrap(True)
        local_model.layout.addWidget(self.hardware_status)
        cards.addWidget(local_model)

        operation = SettingCard(
            self._("Scan this Inbox"),
            self._("Primary one-shot action: analyse the configured batch, skip recorded IDs, apply only permitted moves, then unload the model."),
        )
        operation.setObjectName("scanCard")
        self.scan_card = operation
        self.calibration_status = QLabel(self._("Calibration not checked yet"))
        self.calibration_status.setObjectName("connectionPartial")
        self.calibration_status.setWordWrap(True)
        operation.layout.addWidget(self.calibration_status)
        operation_buttons = QGridLayout()
        operation_buttons.setHorizontalSpacing(10)
        operation_buttons.setVerticalSpacing(8)
        self.scan_button = QPushButton(self._("Start Inbox scan with Gemma"))
        self.scan_button.setObjectName("scanPrimaryButton")
        self.scan_button.setAccessibleName(self._("Start Inbox scan"))
        self.scan_button.setToolTip(self._(
            "Save the current preferences and start one local, one-shot Inbox scan."
        ))
        self.quiz_button = QPushButton(self._("Recommended onboarding quiz"))
        self.quiz_button.setObjectName("secondaryButton")
        self.review_quarantine_button = QPushButton(
            self._("Review filter candidates")
        )
        self.review_quarantine_button.setObjectName("secondaryButton")
        self.review_quarantine_button.setToolTip(self._(
            "Review existing Quarantine decisions and borderline cleanup candidates. Keep and Don't keep answers count as Safety Governor evidence."
        ))
        self.cancel_operation_button = QPushButton(self._("Stop"))
        self.cancel_operation_button.setObjectName("secondaryButton")
        self.cancel_operation_button.setEnabled(False)
        operation_buttons.addWidget(self.scan_button, 0, 0, 1, 3)
        operation_buttons.addWidget(self.quiz_button, 1, 0)
        operation_buttons.addWidget(self.review_quarantine_button, 1, 1)
        operation_buttons.addWidget(self.cancel_operation_button, 1, 2)
        operation_buttons.setColumnStretch(3, 1)
        operation.layout.addLayout(operation_buttons)
        self.operation_progress = QProgressBar()
        self.operation_progress.setRange(0, 100)
        self.operation_progress.setValue(0)
        self.operation_progress.setFormat(self._("Ready"))
        operation.layout.addWidget(self.operation_progress)
        self.operation_summary = QLabel(self._(
            "Recommended first run: answer at least 40 questions for this account."
        ))
        self.operation_summary.setObjectName("fieldHint")
        self.operation_summary.setWordWrap(True)
        operation.layout.addWidget(self.operation_summary)
        self.lumegraph_status = QLabel(self._(
            "LumeGraph builds a private temporal utility graph. Only a separately verified Proof of Obsolescence may affect policy."
        ))
        self.lumegraph_status.setObjectName("fieldHint")
        self.lumegraph_status.setWordWrap(True)
        operation.layout.addWidget(self.lumegraph_status)
        self.proof_status = QLabel(self._(
            "Proof of Obsolescence · verifies closure witnesses locally. It may promote Review to reversible Quarantine, never directly to Trash."
        ))
        self.proof_status.setObjectName("fieldHint")
        self.proof_status.setWordWrap(True)
        operation.layout.addWidget(self.proof_status)
        estimate_row = QHBoxLayout()
        self.duration_estimate_button = QPushButton(
            self._("Estimate scan duration")
        )
        self.duration_estimate_button.setObjectName("secondaryButton")
        self.duration_estimate_button.setEnabled(False)
        estimate_row.addWidget(self.duration_estimate_button)
        estimate_row.addStretch(1)
        operation.layout.addLayout(estimate_row)
        self.duration_estimate_status = QLabel(self._(
            "Counts eligible, unprocessed IDs only; it does not read message bodies, load the model, or change email."
        ))
        self.duration_estimate_status.setObjectName("fieldHint")
        self.duration_estimate_status.setWordWrap(True)
        operation.layout.addWidget(self.duration_estimate_status)
        # The scan is the product's main action, not another setting. Keep it as
        # the first card in the scroll area on macOS, Windows, and Linux.
        cards.insertWidget(0, operation)

        optional_modules = SettingCard(
            self._("Optional local analyses"),
            self._(
                "These modules are independent of the ordinary filter. Disable any of them to shorten a scan; the model still runs locally and the selected mailbox safeguards remain active."
            ),
        )
        optional_modules.setObjectName("optionalModulesCard")
        self.threat_protection_checkbox = QCheckBox(
            self._("Phishing and scam protection")
        )
        self.threat_protection_checkbox.setAccessibleName(
            self._("Phishing and scam protection")
        )
        self.threat_semantic_mode = QComboBox()
        self.threat_semantic_mode.addItem(
            self._("Technical screening only · fastest"),
            ThreatSemanticMode.TECHNICAL_ONLY,
        )
        self.threat_semantic_mode.addItem(
            self._("Technical screening + local AI only on technical alerts"),
            ThreatSemanticMode.CONFIRMED_SEMANTIC,
        )
        self.threat_semantic_mode.addItem(
            self._("Technical screening + local AI for suspicious email"),
            ThreatSemanticMode.TARGETED_SEMANTIC,
        )
        self.threat_semantic_mode.setAccessibleName(
            self._("Threat protection depth")
        )
        self.lumegraph_checkbox = QCheckBox(self._("LumeGraph analysis"))
        self.lumegraph_checkbox.setAccessibleName(self._("LumeGraph analysis"))
        self.obsolescence_proof_checkbox = QCheckBox(
            self._("Proof of Obsolescence checks")
        )
        self.obsolescence_proof_checkbox.setAccessibleName(
            self._("Proof of Obsolescence checks")
        )
        for checkbox in (
            self.threat_protection_checkbox,
            self.lumegraph_checkbox,
            self.obsolescence_proof_checkbox,
        ):
            checkbox.setChecked(True)
            optional_modules.layout.addWidget(checkbox)
        optional_modules.add_field(
            self._("Threat protection depth"),
            self._(
                "Fast mode uses technical signals only. Targeted mode asks the local model only about messages that already have a technical warning signal."
            ),
            self.threat_semantic_mode,
        )
        optional_modules_hint = QLabel(self._(
            "Targeted phishing analysis no longer adds a model pass to every email. LumeGraph may add lifecycle passes only for candidate messages; Proof checks existing local evidence."
        ))
        optional_modules_hint.setObjectName("fieldHint")
        optional_modules_hint.setWordWrap(True)
        optional_modules.layout.addWidget(optional_modules_hint)
        cards.insertWidget(1, optional_modules)

        threat = SettingCard(
            self._("Local phishing and scam protection"),
            self._("Independent technical signals and local AI identify high-risk messages. They receive additive visible markers that preserve Inbox and existing labels or flags, and this module can never authorise cleanup."),
        )
        threat.setObjectName("threatCard")
        self.threat_card = threat
        self.threat_status = QLabel(self._(
            "Local Threat Protection checks independent technical evidence and, in targeted mode, local AI evidence only for technically suspicious messages. High-risk messages receive additive visible markers that preserve Inbox and existing labels or flags, and never authorise cleanup."
        ))
        self.threat_status.setObjectName("fieldHint")
        self.threat_status.setWordWrap(True)
        threat.layout.addWidget(self.threat_status)
        threat_marker_guidance = QLabel(self._(
            "Visible phishing marker: Gmail adds the InboxLume/Sospetto phishing label while preserving INBOX and all other labels. Yahoo adds only the IMAP \\Flagged flag while preserving Inbox and all existing flags; its star is not exclusive to InboxLume. Neither action can authorise cleanup or Trash."
        ))
        threat_marker_guidance.setObjectName("fieldHint")
        threat_marker_guidance.setWordWrap(True)
        threat.layout.addWidget(threat_marker_guidance)
        threat_backtest_row = QHBoxLayout()
        self.threat_backtest_button = QPushButton(
            self._("Run synthetic threat backtest")
        )
        self.threat_backtest_button.setObjectName("secondaryButton")
        self.threat_backtest_button.setEnabled(False)
        self.threat_backtest_button.setToolTip(self._(
            "Uses only the packaged synthetic corpus and selected local model. It never connects to an email account."
        ))
        threat_backtest_row.addWidget(self.threat_backtest_button)
        threat_backtest_row.addStretch(1)
        threat.layout.addLayout(threat_backtest_row)
        self.threat_backtest_status = QLabel(self._(
            "Run this after selecting a model to measure preliminary precision and recall on synthetic English, Italian, and mixed-language cases. Passing it does not certify production safety."
        ))
        self.threat_backtest_status.setObjectName("fieldHint")
        self.threat_backtest_status.setWordWrap(True)
        threat.layout.addWidget(self.threat_backtest_status)
        # Keep protection visible near the primary action on all platforms.
        cards.insertWidget(2, threat)

        governor = SettingCard(
            self._("Personal Safety Governor"),
            self._("Local evidence from your corrections, isolated by account and model. Operational permissions are calculated separately for Quarantine and Direct Trash."),
        )
        governor.setObjectName("governorCard")
        self.governor_status = QLabel(self._(
            "Safety evidence is available after the account is connected and local scans have been reviewed."
        ))
        self.governor_status.setObjectName("connectionOff")
        self.governor_status.setWordWrap(True)
        governor.layout.addWidget(self.governor_status)
        self.governor_enforced_checkbox = QCheckBox(
            self._("Use the operational Safety Governor")
        )
        self.governor_enforced_checkbox.setAccessibleName(
            self._("Operational Safety Governor")
        )
        governor.layout.addWidget(self.governor_enforced_checkbox)
        governor_explanation = QLabel(self._(
            "The ordinary destination remains independent. The Governor may also authorise Direct Trash only for a supported model and families with at least 299 conclusive reviews and zero Keep corrections."
        ))
        governor_explanation.setObjectName("fieldHint")
        governor_explanation.setWordWrap(True)
        governor.layout.addWidget(governor_explanation)
        self.governor_capabilities = QLabel()
        self.governor_capabilities.setObjectName("fieldHint")
        self.governor_capabilities.setWordWrap(True)
        governor.layout.addWidget(self.governor_capabilities)
        self.drift_status = QLabel(self._(
            "Temporal preference drift is evaluated from local timestamped corrections and behaviour; it cannot authorise more cleanup."
        ))
        self.drift_status.setObjectName("fieldHint")
        self.drift_status.setWordWrap(True)
        governor.layout.addWidget(self.drift_status)
        backtest_row = QHBoxLayout()
        self.backtest_button = QPushButton(self._("Run local backtest"))
        self.backtest_button.setObjectName("secondaryButton")
        self.backtest_button.setEnabled(False)
        backtest_row.addWidget(self.backtest_button)
        backtest_row.addStretch(1)
        governor.layout.addLayout(backtest_row)
        self.backtest_status = QLabel(self._(
            "The versioned backtest replays only recorded aggregate outcomes. It does not reopen messages or authorise mailbox actions."
        ))
        self.backtest_status.setObjectName("fieldHint")
        self.backtest_status.setWordWrap(True)
        governor.layout.addWidget(self.backtest_status)
        self.backtest_guidance = QLabel(self._(
            "Recommended timing: run it after at least {minimum} conclusive reviews and before enabling the operational Governor. Repeat it after new corrections, restores, or a model/policy change.",
            minimum=DEFAULT_MINIMUM_CONCLUSIVE_REVIEWS,
        ))
        self.backtest_guidance.setObjectName("safeBox")
        self.backtest_guidance.setWordWrap(True)
        governor.layout.addWidget(self.backtest_guidance)
        # Inserted after Destination below: its permissions only make sense once
        # the ordinary selection and destination have been understood.

        selection = SettingCard(
            self._("Message selection"),
            self._("Thresholds decide what may be analysed; they never authorise a move by themselves."),
        )
        selection.setObjectName("selectionCard")
        self.unread_days = QSpinBox()
        self.unread_days.setRange(1, 3650)
        self.unread_days.setSuffix(self._(" days"))
        self.unread_days.setAccessibleName(self._("Minimum age of unread email"))
        selection.add_field(
            self._("Still unread email"),
            self._("Only analyse messages older than the selected number of days."),
            self.unread_days,
        )

        self.otp_days = QSpinBox()
        self.otp_days.setRange(1, 3650)
        self.otp_days.setSuffix(self._(" days"))
        self.otp_days.setAccessibleName(self._("Minimum age of read one-time codes"))
        selection.add_field(
            self._("Read one-time codes"),
            self._("A separate rule for expired OTP and verification codes."),
            self.otp_days,
        )

        self.scan_order = QComboBox()
        self.scan_order.addItem(self._("Newest first"), ScanOrder.NEWEST_FIRST)
        self.scan_order.addItem(self._("Oldest first"), ScanOrder.OLDEST_FIRST)
        self.scan_order.setAccessibleName(self._("Processing order"))
        selection.add_field(
            self._("Processing order"),
            self._("Choose which end of the archive the next batch starts from."),
            self.scan_order,
        )
        cards.addWidget(selection)

        execution = SettingCard(
            self._("Execution"),
            self._("Every session is one-shot: the local model is unloaded when the session finishes."),
        )
        execution.setObjectName("executionCard")
        self.batch_size = QSpinBox()
        self.batch_size.setRange(0, 500)
        self.batch_size.setSingleStep(10)
        self.batch_size.setSuffix(self._(" emails"))
        self.batch_size.setSpecialValueText(self._("All eligible"))
        self.batch_size.setAccessibleName(self._("Maximum email per session"))
        execution.add_field(
            self._("Maximum per session"),
            self._("Choose All eligible to continue until no eligible, unprocessed email remains. Later sessions always skip messages already recorded."),
            self.batch_size,
        )

        self.quiz_size = QSpinBox()
        self.quiz_size.setRange(1, 500)
        self.quiz_size.setSingleStep(10)
        self.quiz_size.setSuffix(self._(" questions"))
        self.quiz_size.setAccessibleName(self._("Quiz question count"))
        execution.add_field(
            self._("Optional quiz"),
            self._("Maximum number of new examples shown when you want to correct the model."),
            self.quiz_size,
        )
        cards.addWidget(execution)

        destination = SettingCard(
            self._("Destination for safe suggestions"),
            self._("This preference is separate for every account and only affects future scans."),
        )
        destination.setObjectName("destinationCard")
        self.quarantine_radio = QRadioButton(self._("Quarantine — recommended"))
        self.trash_radio = QRadioButton(self._("Direct Trash — skip Quarantine"))
        self.destination_group = QButtonGroup(self)
        self.destination_group.addButton(self.quarantine_radio)
        self.destination_group.addButton(self.trash_radio)
        destination.layout.addWidget(self.quarantine_radio)
        destination.layout.addWidget(self.trash_radio)
        self.destination_notice = QLabel()
        self.destination_notice.setWordWrap(True)
        destination.layout.addWidget(self.destination_notice)
        cards.addWidget(destination)
        cards.addWidget(governor)

        schedule = SettingCard(
            self._("One-shot schedule"),
            self._("Optional and isolated per account. It uses the operating system's native scheduler, so neither InboxLume nor the model stays running."),
        )
        schedule.setObjectName("scheduleCard")
        self.schedule_status = QLabel(self._("Schedule not checked yet"))
        self.schedule_status.setObjectName("connectionOff")
        self.schedule_status.setWordWrap(True)
        schedule.layout.addWidget(self.schedule_status)

        self.schedule_time = QTimeEdit()
        self.schedule_time.setDisplayFormat("HH:mm")
        self.schedule_time.setAccessibleName(self._("Schedule time"))
        schedule.add_field(
            self._("Time"),
            self._("The computer's local time at which the scan should start."),
            self.schedule_time,
        )
        self.schedule_frequency = QComboBox()
        self.schedule_frequency.addItem(self._("Every day"), ScheduleFrequency.DAILY)
        self.schedule_frequency.addItem(
            self._("Monday to Friday"), ScheduleFrequency.WEEKDAYS
        )
        self.schedule_frequency.addItem(
            self._("Once a week"), ScheduleFrequency.WEEKLY
        )
        schedule.add_field(
            self._("Frequency"),
            self._("Choose a new value and apply again to change the frequency."),
            self.schedule_frequency,
        )
        self.schedule_weekday = QComboBox()
        for number, label in enumerate(
            (
                self._("Monday"),
                self._("Tuesday"),
                self._("Wednesday"),
                self._("Thursday"),
                self._("Friday"),
                self._("Saturday"),
                self._("Sunday"),
            ),
            start=1,
        ):
            self.schedule_weekday.addItem(label, number)
        schedule.add_field(
            self._("Weekday"),
            self._("Used only with weekly frequency."),
            self.schedule_weekday,
        )
        schedule_buttons = QHBoxLayout()
        self.apply_schedule_button = QPushButton(self._("Apply / update"))
        self.apply_schedule_button.setObjectName("primaryButton")
        self.remove_schedule_button = QPushButton(self._("Disable"))
        self.remove_schedule_button.setObjectName("secondaryButton")
        schedule_buttons.addWidget(self.apply_schedule_button)
        schedule_buttons.addWidget(self.remove_schedule_button)
        schedule_buttons.addStretch(1)
        schedule.layout.addLayout(schedule_buttons)
        self.schedule_advice = QLabel(self._(
            "Tip: choose a time when the computer is on but not under heavy load. The local model temporarily uses RAM and CPU/GPU, then exits and releases memory after the batch."
        ))
        self.schedule_advice.setObjectName("safeBox")
        self.schedule_advice.setWordWrap(True)
        schedule.layout.addWidget(self.schedule_advice)
        cards.addWidget(schedule)
        cards.addStretch(1)
        scroll.setWidget(scroll_content)
        outer.addWidget(scroll, 1)

        footer = QHBoxLayout()
        self.status_text = QLabel(self._("Preferences contain no credentials or email text."))
        self.status_text.setObjectName("statusText")
        self.status_text.setWordWrap(True)
        footer.addWidget(self.status_text, 1)
        self.discard_button = QPushButton(self._("Discard changes"))
        self.discard_button.setObjectName("secondaryButton")
        self.save_button = QPushButton(self._("Save preferences"))
        self.save_button.setObjectName("primaryButton")
        footer.addWidget(self.discard_button)
        footer.addWidget(self.save_button)
        outer.addLayout(footer)
        return container

    def _connect_signals(self) -> None:
        self.account_list.currentRowChanged.connect(self._account_changed)
        self.add_account_button.clicked.connect(self._add_account)
        self.remove_account_button.clicked.connect(self._remove_account)
        self.english_language_button.clicked.connect(
            lambda: self._language_changed(UiLanguage.ENGLISH)
        )
        self.italian_language_button.clicked.connect(
            lambda: self._language_changed(UiLanguage.ITALIAN)
        )
        self.connect_button.clicked.connect(self._connect_account)
        self.action_permission_button.clicked.connect(self._connect_gmail_actions)
        self.test_connection_button.clicked.connect(self._test_connection)
        self.disconnect_button.clicked.connect(self._disconnect_account)
        self.account_display_name.textChanged.connect(self._display_name_changed)
        self.governor_enforced_checkbox.toggled.connect(
            self._governor_enforcement_changed
        )
        for checkbox in (
            self.threat_protection_checkbox,
            self.lumegraph_checkbox,
            self.obsolescence_proof_checkbox,
        ):
            checkbox.toggled.connect(self._optional_module_changed)
        self.threat_semantic_mode.currentIndexChanged.connect(
            self._threat_semantic_mode_changed
        )
        self.backtest_button.clicked.connect(self._run_safety_backtest)
        self.threat_backtest_button.clicked.connect(
            self._start_threat_backtest
        )
        self.duration_estimate_button.clicked.connect(
            self._run_duration_estimate
        )
        self.scan_button.clicked.connect(self._start_scan)
        self.quiz_button.clicked.connect(self._start_quiz)
        self.review_quarantine_button.clicked.connect(self._start_shadow_review)
        self.cancel_operation_button.clicked.connect(self._cancel_operation)
        self.save_button.clicked.connect(self.save)
        self.discard_button.clicked.connect(self.discard_changes)
        self.quarantine_radio.toggled.connect(self._destination_changed)
        self.trash_radio.toggled.connect(self._destination_changed)
        self.schedule_frequency.currentIndexChanged.connect(
            self._schedule_draft_changed
        )
        self.schedule_time.timeChanged.connect(self._schedule_draft_changed)
        self.schedule_weekday.currentIndexChanged.connect(
            self._schedule_draft_changed
        )
        self.apply_schedule_button.clicked.connect(self._apply_schedule)
        self.remove_schedule_button.clicked.connect(self._remove_schedule)
        for control in (
            self.unread_days,
            self.otp_days,
            self.batch_size,
            self.quiz_size,
        ):
            control.valueChanged.connect(self._mark_dirty)
        for control in (self.unread_days, self.otp_days, self.batch_size):
            control.valueChanged.connect(self._reset_duration_estimate)
        self.scan_order.currentIndexChanged.connect(self._mark_dirty)
        self.model_profile.currentIndexChanged.connect(self._model_changed)

    def _language_changed(self, language: UiLanguage) -> None:
        if language is self.settings.language:
            return
        if self.current_account_id is not None:
            self._collect_form(self.current_account_id)
        previous_language = self.settings.language
        in_memory_updated = self.settings.replacing_language(language)
        try:
            persisted_updated = self.store.load().replacing_language(language)
            self.store.save(persisted_updated)
        except (OSError, ValueError) as exc:
            self.english_language_button.setChecked(
                previous_language is UiLanguage.ENGLISH
            )
            self.italian_language_button.setChecked(
                previous_language is UiLanguage.ITALIAN
            )
            QMessageBox.critical(self, "InboxLume", str(exc))
            return
        # Language applies immediately on restart; unsaved account drafts stay
        # drafts and are neither discarded nor silently persisted.
        self.settings = in_memory_updated
        QMessageBox.information(
            self,
            "InboxLume",
            ui_text(language, "Restart InboxLume to apply the interface language."),
        )

    def _selected_id(self) -> str:
        item = self.account_list.currentItem()
        if item is None:
            raise RuntimeError("nessun account selezionato")
        value = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(value, str):
            raise RuntimeError("account selezionato non valido")
        return value

    def _add_account(self) -> None:
        if self._process is not None or self._schedule_busy or self._estimate_busy:
            return
        if self.current_account_id is not None:
            self._collect_form(self.current_account_id)
        dialog = AddAccountDialog(self.settings.language, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        provider = dialog.provider.currentData()
        if not isinstance(provider, ProviderKind):
            provider = ProviderKind(str(provider))
        try:
            updated = self.settings.adding_account(
                provider,
                dialog.name.text(),
                model_profile=self.recommended_model or LocalModelProfile.QWEN8,
            )
            new_account = updated.accounts[-1]
            persisted = self.store.load().adding_account(
                provider,
                new_account.display_name,
                account_id=new_account.account_id,
                model_profile=new_account.model_profile,
            )
            self.store.save(persisted)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, self._("Account not added"), str(exc))
            return
        self.settings = updated
        self.dirty = updated != persisted
        self.current_account_id = None
        self._populate_account_list(new_account.account_id)
        self.status_text.setText(self._(
            "Account added. Connect it now and complete the recommended onboarding quiz."
        ))

    def _remove_account(self) -> None:
        if (
            self._process is not None
            or self._schedule_busy
            or self._estimate_busy
            or self.current_account_id is None
        ):
            return
        account = self.settings.account(self.current_account_id)
        if account.schedule.enabled or self._native_schedule_installed:
            QMessageBox.information(
                self,
                self._("Disable the schedule first"),
                self._("Remove this account's scheduled task first, so no orphaned native task remains on the system."),
            )
            return
        if self.auth_service is None:
            self._connection_state = ConnectionState.ERROR
            self._connection_read_access = False
            QMessageBox.warning(
                self,
                self._("Removal unavailable"),
                self._("Local credentials could not be checked. Try again when the credential manager is available."),
            )
            return
        status = self.auth_service.status(account.account_id, account.provider)
        if status.state is not ConnectionState.NOT_CONFIGURED:
            QMessageBox.information(
                self,
                self._("Disconnect the account first"),
                self._("Use Disconnect first to avoid orphaned credentials. Disconnecting never changes email."),
            )
            return
        answer = QMessageBox.question(
            self,
            self._("Remove this account from InboxLume?"),
            self._("The account will disappear from the list. Email will not be touched, and the local HMAC-protected history will not be deleted."),
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            updated, persisted = scoped_account_removal(
                self.settings,
                self.store.load(),
                account.account_id,
            )
            self.store.save(persisted)
        except (KeyError, OSError, ValueError) as exc:
            QMessageBox.critical(self, self._("Account not removed"), str(exc))
            return
        self.settings = updated
        self.dirty = updated != persisted
        self.current_account_id = None
        self._populate_account_list()
        self.status_text.setText(self._("Account removed from InboxLume; no email changed."))

    def _account_changed(self, _: int) -> None:
        if self.account_list.currentItem() is None:
            return
        if self.current_account_id is not None:
            self._collect_form(self.current_account_id)
        self.current_account_id = self._selected_id()
        self._load_form(self.settings.account(self.current_account_id))

    def _load_form(self, account: AccountSettings) -> None:
        controls = (
            self.account_display_name,
            self.governor_enforced_checkbox,
            self.threat_protection_checkbox,
            self.threat_semantic_mode,
            self.lumegraph_checkbox,
            self.obsolescence_proof_checkbox,
            self.unread_days,
            self.otp_days,
            self.batch_size,
            self.quiz_size,
            self.scan_order,
            self.model_profile,
            self.quarantine_radio,
            self.trash_radio,
            self.schedule_time,
            self.schedule_frequency,
            self.schedule_weekday,
        )
        for control in controls:
            control.blockSignals(True)
        try:
            self.account_display_name.setText(account.display_name)
            self.governor_enforced_checkbox.setChecked(
                account.safety_governor_enforced
            )
            self.threat_protection_checkbox.setChecked(
                account.threat_protection_enabled
            )
            semantic_index = self.threat_semantic_mode.findData(
                account.threat_semantic_mode
            )
            self.threat_semantic_mode.setCurrentIndex(max(0, semantic_index))
            self.lumegraph_checkbox.setChecked(account.lumegraph_enabled)
            self.obsolescence_proof_checkbox.setChecked(
                account.obsolescence_proof_enabled
            )
            self.unread_days.setValue(account.unread_age_days)
            self.otp_days.setValue(account.read_one_time_code_age_days)
            self.batch_size.setValue(account.batch_size)
            self.quiz_size.setValue(account.quiz_size)
            order_index = self.scan_order.findData(account.scan_order)
            self.scan_order.setCurrentIndex(max(0, order_index))
            model_index = self.model_profile.findData(account.model_profile)
            self.model_profile.setCurrentIndex(max(0, model_index))
            self.quarantine_radio.setChecked(
                account.destination is MessageDestination.QUARANTINE
            )
            self.trash_radio.setChecked(
                account.destination is MessageDestination.TRASH
            )
            self.schedule_time.setTime(
                QTime(account.schedule.hour, account.schedule.minute)
            )
            frequency_index = self.schedule_frequency.findData(
                account.schedule.frequency
            )
            self.schedule_frequency.setCurrentIndex(max(0, frequency_index))
            weekday_index = self.schedule_weekday.findData(account.schedule.weekday)
            self.schedule_weekday.setCurrentIndex(max(0, weekday_index))
        finally:
            for control in controls:
                control.blockSignals(False)
        provider_name = "Gmail" if account.provider is ProviderKind.GMAIL else "Yahoo"
        self.threat_semantic_mode.setEnabled(
            account.threat_protection_enabled
            and self._process is None
            and not self._schedule_busy
            and not self._estimate_busy
        )
        self.page_title.setText(
            account.display_name or self._("Rules for {provider}", provider=provider_name)
        )
        self._refresh_destination_notice()
        self._refresh_model_status()
        self._refresh_connection_status()
        self._refresh_calibration_status()
        self._refresh_threat_status()
        self._refresh_lumegraph_status()
        self._refresh_safety_governor()
        self._refresh_schedule_frequency_visibility()
        self._refresh_schedule_status()
        self._reset_duration_estimate()

    def _collect_form(self, account_id: str) -> None:
        destination = (
            MessageDestination.TRASH
            if self.trash_radio.isChecked()
            else MessageDestination.QUARANTINE
        )
        order = self.scan_order.currentData()
        if not isinstance(order, ScanOrder):
            order = ScanOrder(str(order))
        selected_model = self.model_profile.currentData()
        if not isinstance(selected_model, LocalModelProfile):
            selected_model = LocalModelProfile(str(selected_model))
        self.settings = self.settings.replacing_account(
            account_id,
            display_name=self.account_display_name.text().strip(),
            safety_governor_enforced=self.governor_enforced_checkbox.isChecked(),
            threat_protection_enabled=self.threat_protection_checkbox.isChecked(),
            threat_semantic_mode=self._selected_threat_semantic_mode(),
            lumegraph_enabled=self.lumegraph_checkbox.isChecked(),
            obsolescence_proof_enabled=self.obsolescence_proof_checkbox.isChecked(),
            unread_age_days=self.unread_days.value(),
            read_one_time_code_age_days=self.otp_days.value(),
            scan_order=order,
            batch_size=self.batch_size.value(),
            quiz_size=self.quiz_size.value(),
            destination=destination,
            model_profile=selected_model,
        )

    def _selected_model_profile(self) -> LocalModelProfile:
        selected = self.model_profile.currentData()
        if isinstance(selected, LocalModelProfile):
            return selected
        return LocalModelProfile(str(selected))

    def _selected_threat_semantic_mode(self) -> ThreatSemanticMode:
        selected = self.threat_semantic_mode.currentData()
        if isinstance(selected, ThreatSemanticMode):
            return selected
        return ThreatSemanticMode(str(selected))

    def _selected_model_is_ready(self) -> bool:
        try:
            status = self.model_availability[self._selected_model_profile()]
        except (KeyError, ValueError):
            return False
        return status.available

    def _refresh_model_status(self) -> None:
        profile = self._selected_model_profile()
        spec = model_spec(profile)
        status = self.model_availability[profile]
        recommended = (
            self._(" · recommended on this computer")
            if profile is self.recommended_model
            else ""
        )
        if status.available:
            self.model_status.setObjectName(
                "connectionPartial" if status.memory_warning else "connectionReady"
            )
            warning = (
                self._(" · memory below the recommended amount")
                if status.memory_warning
                else ""
            )
            self.model_status.setText(self._(
                "Available{recommended}{warning}. {detail}\n{notice}",
                recommended=recommended,
                warning=warning,
                detail=self._(status.detail),
                notice=self._(spec.quality_notice),
            ))
        else:
            self.model_status.setObjectName("connectionOff")
            self.model_status.setText(self._(
                "Unavailable on this computer: {detail}\n{notice}",
                detail=self._(status.detail),
                notice=self._(spec.quality_notice),
            ))
        self._refresh_destination_capabilities()
        self.scan_button.setText(self._(
            "Start Inbox scan · {tier}", tier=self._(spec.tier)
        ))
        self._repolish(self.model_status)
        self._refresh_destination_notice()
        self._refresh_operation_availability()

    def _model_changed(self, *_: Any) -> None:
        spec = model_spec(self._selected_model_profile())
        if not spec.direct_trash_allowed and self.trash_radio.isChecked():
            self.quarantine_radio.setChecked(True)
        self._refresh_model_status()
        self._refresh_threat_status()
        self._refresh_lumegraph_status()
        self._refresh_safety_governor()
        self._reset_duration_estimate()
        self._mark_dirty()

    def _governor_enforcement_changed(self, *_: Any) -> None:
        self._refresh_safety_governor()
        self._refresh_destination_capabilities()
        self._refresh_destination_notice()
        self._reset_duration_estimate()
        self._mark_dirty()

    def _refresh_safety_governor(self) -> None:
        if not hasattr(self, "governor_status") or self.current_account_id is None:
            return
        if self.auth_service is None or not self._connection_read_access:
            self.backtest_button.setEnabled(False)
            self._set_governor_operational_available(False)
            self._governor_quarantine_ready = False
            self._governor_trash_ready = False
            self.governor_capabilities.setText(self._(
                "Operational choices unlock only from qualified local evidence."
            ))
            self.governor_status.setObjectName("connectionOff")
            self.governor_status.setText(self._(
                "Safety evidence is available after the account is connected and local scans have been reviewed."
            ))
            self.drift_status.setObjectName("fieldHint")
            self.drift_status.setText(self._(
                "Temporal preference drift becomes available from timestamped local evidence after the account is connected."
            ))
            self._repolish(self.governor_status)
            self._repolish(self.drift_status)
            self._refresh_destination_notice()
            return
        account = self.settings.account(self.current_account_id)
        scan_profile = scan_profile_for_model(self._selected_model_profile())
        try:
            report = local_safety_governor_report(
                self._state_db(account),
                account.account_id,
                self.auth_service.store,
                scan_profile,
            )
            drift_report = local_temporal_drift_report(
                self._state_db(account),
                account.account_id,
                self.auth_service.store,
                scan_profile,
            )
        except (OSError, RuntimeError, ValueError):
            self.backtest_button.setEnabled(False)
            self._set_governor_operational_available(False)
            self._governor_quarantine_ready = False
            self._governor_trash_ready = False
            self.governor_capabilities.setText(self._(
                "Operational choices unlock only from qualified local evidence."
            ))
            self.governor_status.setObjectName("connectionOff")
            self.governor_status.setText(self._(
                "Safety evidence is available after the account is connected and local scans have been reviewed."
            ))
            self.drift_status.setObjectName("fieldHint")
            self.drift_status.setText(self._(
                "Temporal preference drift is not available from the current local evidence."
            ))
            self._repolish(self.governor_status)
            self._repolish(self.drift_status)
            self._refresh_destination_notice()
            return

        evidence = report.overall
        self.backtest_guidance.setText(self._(
            "Recommended timing: run it after at least {minimum} conclusive reviews and before enabling the operational Governor. Current evidence: {current}/{minimum}. Repeat it after new corrections, restores, or a model/policy change.",
            minimum=DEFAULT_MINIMUM_CONCLUSIVE_REVIEWS,
            current=evidence.conclusive_reviews,
        ))
        self.backtest_button.setEnabled(
            self._process is None and not self._schedule_busy
        )
        governor_available = operational_governor_available(report)
        self._set_governor_operational_available(governor_available)
        gate = operational_quarantine_gate(
            report,
            enforced=True,
            protective_drift_families=drift_report.restricted_families,
        )
        self._governor_quarantine_ready = bool(gate.authorized_families)
        self._governor_trash_ready = bool(
            gate.direct_trash_authorized_families
        )
        if governor_available:
            self.governor_capabilities.setText(self._(
                "Adaptive state: {blocked} families restricted by repeated errors or protective drift · {qualified} statistically qualified · Governor Trash authority for {trash} families (minimum {minimum}, zero Keep corrections).",
                blocked=len(gate.blocked_families),
                qualified=len(gate.authorized_families),
                trash=len(gate.direct_trash_authorized_families),
                minimum=DIRECT_TRASH_MINIMUM_CONCLUSIVE_REVIEWS,
            ))
        else:
            self.governor_capabilities.setText(self._(
                "The operational Governor unlocks after {minimum} conclusive reviews for this account and model ({current}/{minimum}). Until then it stays shadow-only and the ordinary filter is unchanged.",
                minimum=DEFAULT_MINIMUM_CONCLUSIVE_REVIEWS,
                current=evidence.conclusive_reviews,
            ))
        self._show_temporal_drift(drift_report)
        operational = self.governor_enforced_checkbox.isChecked()
        mode = self._("Operational gate") if operational else self._("Shadow only")
        if evidence.proposals == 0:
            self.governor_status.setObjectName("connectionOff")
            self.governor_status.setText(self._(
                "{mode} · no Quarantine proposals recorded yet for this account and model.",
                mode=mode,
            ))
        elif evidence.conclusive_reviews == 0:
            self.governor_status.setObjectName("connectionPartial")
            self.governor_status.setText(self._(
                "{mode} · {proposals} Quarantine proposals · no conclusive matching quiz answers yet.",
                mode=mode,
                proposals=evidence.proposals,
            ))
        else:
            if operational:
                state_text = self._(
                    "The ordinary filter remains active. {blocked} families are restricted by concrete repeated-error evidence or protective drift; the Governor has Direct Trash authority for {trash} strictly qualified families.",
                    blocked=len(gate.blocked_families),
                    trash=len(gate.direct_trash_authorized_families),
                )
            else:
                state_text = {
                    GovernorStatus.COLLECTING: self._("Collecting evidence."),
                    GovernorStatus.NOT_QUALIFIED: self._(
                        "Not qualified at the selected risk target."
                    ),
                    GovernorStatus.QUALIFIED_SHADOW: self._(
                        "Shadow threshold met; this still authorises no actions."
                    ),
                }[evidence.status]
            self.governor_status.setObjectName(
                "connectionReady"
                if evidence.status is GovernorStatus.QUALIFIED_SHADOW
                else "connectionPartial"
            )
            self.governor_status.setText(self._(
                "{mode} · {reviews} conclusive reviews / {proposals} proposals · {errors} Keep corrections · 95% upper error bound {upper}% (target ≤ {target}%). {state}",
                mode=mode,
                reviews=evidence.conclusive_reviews,
                proposals=evidence.proposals,
                errors=evidence.false_cleanup,
                upper=f"{(evidence.upper_false_cleanup_rate or 0.0) * 100:.1f}",
                target=f"{evidence.target_false_cleanup_rate * 100:.1f}",
                state=state_text,
            ))
        self._repolish(self.governor_status)
        self._refresh_destination_notice()

    def _show_temporal_drift(self, report: TemporalDriftReport) -> None:
        recent_messages = sum(
            family.recent.message_count for family in report.families
        )
        historical_messages = sum(
            family.historical.message_count for family in report.families
        )
        restricted = sorted(report.restricted_families)
        shifted = sorted(report.shifted_families - report.restricted_families)
        stable = any(
            family.status is TemporalDriftStatus.STABLE
            for family in report.families
        )
        if restricted:
            self.drift_status.setObjectName("warningBox")
            if not self.governor_enforced_checkbox.isChecked():
                effect = self._(
                    "the ordinary filter is unchanged while the Governor is off"
                )
            elif self.trash_radio.isChecked():
                effect = self._(
                    "Governor Trash authority is revoked for these families; ordinary Direct Trash remains independent"
                )
            else:
                effect = self._(
                    "the active Governor restricts Quarantine cleanup for these families"
                )
            text = self._(
                "Preference drift · protective change in {families} · recent/historical messages {recent}/{historical}; {effect}. Declining interest never authorises more cleanup.",
                families=", ".join(restricted),
                recent=recent_messages,
                historical=historical_messages,
                effect=effect,
            )
        elif shifted:
            self.drift_status.setObjectName("connectionPartial")
            text = self._(
                "Preference drift · a non-authorising change is visible in {families} · recent/historical messages {recent}/{historical}. More cleanup is never unlocked by declining or weak interest.",
                families=", ".join(shifted),
                recent=recent_messages,
                historical=historical_messages,
            )
        elif stable:
            self.drift_status.setObjectName("safeBox")
            text = self._(
                "Preference drift · no material change detected across the recent {recent_days}-day window and the preceding history · messages {recent}/{historical}.",
                recent_days=report.recent_days,
                recent=recent_messages,
                historical=historical_messages,
            )
        else:
            self.drift_status.setObjectName("fieldHint")
            text = self._(
                "Preference drift · collecting evidence across a recent {recent_days}-day window and history up to {historical_days} days · messages {recent}/{historical}. No operational restriction is inferred yet.",
                recent_days=report.recent_days,
                historical_days=report.historical_days,
                recent=recent_messages,
                historical=historical_messages,
            )
        self.drift_status.setText(text)
        self._repolish(self.drift_status)

    def _run_safety_backtest(self) -> None:
        if (
            self.current_account_id is None
            or self.auth_service is None
            or not self._connection_read_access
            or self._process is not None
            or self._schedule_busy
        ):
            return
        account = self.settings.account(self.current_account_id)
        profile = scan_profile_for_model(self._selected_model_profile())
        self.backtest_button.setEnabled(False)
        try:
            report = local_versioned_safety_backtest(
                self._state_db(account),
                account.account_id,
                self.auth_service.store,
                profile,
            )
        except (OSError, RuntimeError, ValueError) as exc:
            self.backtest_status.setObjectName("warningBox")
            self.backtest_status.setText(self._(
                "Local backtest unavailable: {error}", error=exc
            ))
        else:
            evidence = report.safety_report.overall
            upper = (
                self._("not available")
                if evidence.upper_false_cleanup_rate is None
                else f"{evidence.upper_false_cleanup_rate * 100:.1f}%"
            )
            if report.trend is BacktestTrend.NO_EVIDENCE:
                object_name = "connectionOff"
                message = self._(
                    "Backtest {version}: no recorded Quarantine proposals exist for this account and model yet. No message was reopened.",
                    version=report.engine_version,
                )
            elif report.trend is BacktestTrend.PROTECTIVE_REGRESSION:
                object_name = "warningBox"
                message = self._(
                    "Backtest {version}: protective regression detected · {errors} new Keep/restore corrections in {families} families · {reviews}/{proposals} conclusive · upper bound {upper}. No mailbox action was authorised.",
                    version=report.engine_version,
                    errors=report.false_cleanup_delta,
                    families=len(report.regressed_families),
                    reviews=evidence.conclusive_reviews,
                    proposals=evidence.proposals,
                    upper=upper,
                )
            else:
                object_name = "safeBox"
                state = {
                    BacktestTrend.BASELINE: self._("baseline recorded"),
                    BacktestTrend.UNCHANGED: self._("unchanged since the last snapshot"),
                    BacktestTrend.STABLE: self._("stable"),
                    BacktestTrend.IMPROVED_EVIDENCE: self._("stronger evidence"),
                }[report.trend]
                message = self._(
                    "Backtest {version}: {state} · {reviews}/{proposals} conclusive · {errors} Keep/restore corrections · upper bound {upper}. No message was reopened and no mailbox action was authorised.",
                    version=report.engine_version,
                    state=state,
                    reviews=evidence.conclusive_reviews,
                    proposals=evidence.proposals,
                    errors=evidence.false_cleanup,
                    upper=upper,
                )
            self.backtest_status.setObjectName(object_name)
            self.backtest_status.setText(message)
        finally:
            self._repolish(self.backtest_status)
            self._refresh_operation_availability()

    def _reset_duration_estimate(self, *_: Any) -> None:
        if not hasattr(self, "duration_estimate_status") or self._estimate_busy:
            return
        self.duration_estimate_status.setObjectName("fieldHint")
        self.duration_estimate_status.setText(self._(
            "Counts eligible, unprocessed IDs only; it does not read message bodies, load the model, or change email."
        ))
        self._repolish(self.duration_estimate_status)

    def _refresh_lumegraph_status(self) -> None:
        if self.current_account_id is None or self.auth_service is None:
            return
        account = self.settings.account(self.current_account_id)
        lumegraph_enabled = self.lumegraph_checkbox.isChecked()
        obsolescence_proof_enabled = self.obsolescence_proof_checkbox.isChecked()
        if not lumegraph_enabled:
            self.lumegraph_status.setObjectName("connectionOff")
            self.lumegraph_status.setText(self._(
                "LumeGraph disabled for the next scan. Existing local graph evidence is kept."
            ))
        if not obsolescence_proof_enabled:
            self.proof_status.setObjectName("connectionOff")
            self.proof_status.setText(self._(
                "Proof of Obsolescence disabled for the next scan. Existing local evidence is kept."
            ))
        if not lumegraph_enabled and not obsolescence_proof_enabled:
            self._repolish(self.lumegraph_status)
            self._repolish(self.proof_status)
            return
        try:
            summary = local_lumegraph_summary(
                self._state_db(account),
                account.account_id,
                self.auth_service.store,
                scan_profile_for_model(self._selected_model_profile()),
            )
            proof = local_obsolescence_proof_summary(
                self._state_db(account),
                account.account_id,
                self.auth_service.store,
                scan_profile_for_model(self._selected_model_profile()),
            )
        except (OSError, RuntimeError, ValueError):
            self.lumegraph_status.setObjectName("fieldHint")
            self.lumegraph_status.setText(self._(
                "LumeGraph builds a private temporal utility graph. Only a separately verified Proof of Obsolescence may affect policy."
            ))
            if obsolescence_proof_enabled:
                self.proof_status.setObjectName("fieldHint")
                self.proof_status.setText(self._(
                    "Proof of Obsolescence · verifies closure witnesses locally. It may promote Review to reversible Quarantine, never directly to Trash."
                ))
        else:
            if lumegraph_enabled:
                self.lumegraph_status.setObjectName("safeBox" if int(summary.get("nodes_total", 0)) else "fieldHint")
                self.lumegraph_status.setText(self._(
                    "LumeGraph active · {nodes} private utility nodes · {transitions} temporal transitions · every policy effect requires a verified closure proof.",
                    nodes=int(summary.get("nodes_total", 0)),
                    transitions=int(summary.get("transitions_total", 0)),
                ))
            statuses = proof.get("statuses") if isinstance(proof.get("statuses"), dict) else {}
            unresolved = int(statuses.get("blocked_protected_utility", 0)) + int(
                statuses.get("insufficient_evidence", 0)
            )
            verified = int(proof.get("verified_total", 0))
            if obsolescence_proof_enabled:
                self.proof_status.setObjectName("safeBox" if verified else "fieldHint")
                self.proof_status.setText(self._(
                    "Proof of Obsolescence operational · {verified} verified closure witnesses · {unresolved} protected or insufficient cases · maximum authority: reversible Quarantine.",
                    verified=verified,
                    unresolved=unresolved,
                ))
        self._repolish(self.lumegraph_status)
        self._repolish(self.proof_status)

    def _refresh_threat_status(self) -> None:
        if self.current_account_id is None or self.auth_service is None:
            return
        account = self.settings.account(self.current_account_id)
        if not self.threat_protection_checkbox.isChecked():
            self.threat_status.setObjectName("connectionOff")
            self.threat_status.setText(self._(
                "Local Threat Protection disabled for the next scan. Existing assessments and warning markers are kept."
            ))
            self._repolish(self.threat_status)
            return
        try:
            summary = local_threat_assessment_summary(
                self._state_db(account),
                account.account_id,
                self.auth_service.store,
                scan_profile_for_model(self._selected_model_profile()),
            )
        except (OSError, RuntimeError, ValueError):
            self.threat_status.setObjectName("fieldHint")
            self.threat_status.setText(self._(
                "Local Threat Protection checks independent technical evidence and, in targeted mode, local AI evidence only for technically suspicious messages. High-risk messages receive additive visible markers that preserve Inbox and existing labels or flags, and never authorise cleanup."
            ))
        else:
            assessed = int(summary.get("assessed_total", 0))
            protected = int(summary.get("protective_reviews_total", 0))
            self.threat_status.setObjectName(
                "safeBox" if assessed > 0 and protected == 0 else
                "warningBox" if protected > 0 else "fieldHint"
            )
            self.threat_status.setText(self._(
                "Local Threat Protection active · {assessed} private assessments · {protected} high-risk messages protected overall · no sender, subject, body, link, or provider ID is stored.",
                assessed=assessed,
                protected=protected,
            ))
        self._repolish(self.threat_status)

    def _set_estimate_busy(self, busy: bool) -> None:
        self._estimate_busy = busy
        self.account_list.setEnabled(not busy)
        for control in (
            self.connect_button,
            self.action_permission_button,
            self.test_connection_button,
            self.disconnect_button,
            self.add_account_button,
            self.remove_account_button,
            self.scan_button,
            self.quiz_button,
            self.review_quarantine_button,
            self.backtest_button,
            self.threat_backtest_button,
            self.duration_estimate_button,
            self.unread_days,
            self.otp_days,
            self.scan_order,
            self.batch_size,
            self.quiz_size,
            self.model_profile,
            self.quarantine_radio,
            self.trash_radio,
            self.governor_enforced_checkbox,
            self.threat_protection_checkbox,
            self.threat_semantic_mode,
            self.lumegraph_checkbox,
            self.obsolescence_proof_checkbox,
            self.schedule_time,
            self.schedule_frequency,
            self.schedule_weekday,
            self.apply_schedule_button,
            self.remove_schedule_button,
            self.english_language_button,
            self.italian_language_button,
        ):
            control.setEnabled(not busy)
        if not busy:
            self._refresh_destination_capabilities()
            self._refresh_destination_notice()
            self._refresh_safety_governor()
        self._refresh_operation_availability()

    @staticmethod
    def _format_duration(seconds: float) -> str:
        rounded = max(0, round(seconds))
        if rounded < 90:
            return f"{rounded} sec"
        minutes = round(rounded / 60)
        if minutes < 90:
            return f"{minutes} min"
        hours = minutes // 60
        remainder = minutes % 60
        return f"{hours} h {remainder} min" if remainder else f"{hours} h"

    def _show_duration_estimate(self, estimate: ScanDurationEstimate) -> None:
        if estimate.planned_messages == 0:
            self.duration_estimate_status.setObjectName("safeBox")
            self.duration_estimate_status.setText(self._(
                "No eligible, unprocessed message IDs were found. No body was read and the model was not loaded."
            ))
            self._repolish(self.duration_estimate_status)
            return
        confidence = {
            EstimateConfidence.LOW: self._("low"),
            EstimateConfidence.MEDIUM: self._("medium"),
            EstimateConfidence.HIGH: self._("high"),
        }[estimate.confidence]
        basis = (
            self._("matching local sessions")
            if estimate.basis == "matching_local_sessions"
            else self._("preliminary reference benchmark")
        )
        limit_note = (
            self._(
                " The configured session cap was reached, so more eligible messages may remain."
            )
            if estimate.session_limit_reached
            else ""
        )
        self.duration_estimate_status.setObjectName(
            "safeBox"
            if estimate.confidence is EstimateConfidence.HIGH
            else "connectionPartial"
        )
        self.duration_estimate_status.setText(self._(
            "{count} eligible IDs for this session · estimated {estimate} (range {lower}–{upper}, {confidence} confidence) · based on {basis}.{limit_note} IDs only: no body read, no model loaded, no email changed.",
            count=estimate.planned_messages,
            estimate=self._format_duration(estimate.estimated_seconds),
            lower=self._format_duration(estimate.lower_seconds),
            upper=self._format_duration(estimate.upper_seconds),
            confidence=confidence,
            basis=basis,
            limit_note=limit_note,
        ))
        self._repolish(self.duration_estimate_status)

    def _run_duration_estimate(self) -> None:
        if (
            self.current_account_id is None
            or self.auth_service is None
            or not self._connection_read_access
            or self._process is not None
            or self._schedule_busy
            or self._estimate_busy
        ):
            return
        self._collect_form(self.current_account_id)
        account = self.settings.account(self.current_account_id)
        account_id = account.account_id
        self._set_estimate_busy(True)
        self.duration_estimate_status.setObjectName("connectionPartial")
        self.duration_estimate_status.setText(self._(
            "Counting eligible IDs and calculating a local estimate…"
        ))
        self._repolish(self.duration_estimate_status)

        def action() -> ScanDurationEstimate:
            return local_scan_duration_estimate(
                self._state_db(account),
                self.config_path,
                account,
                self.auth_service.store,
                self.hardware,
            )

        task = BackgroundTask(action)
        self._tasks.add(task)

        def succeeded(result: object) -> None:
            if (
                self.current_account_id == account_id
                and isinstance(result, ScanDurationEstimate)
            ):
                self._show_duration_estimate(result)

        def failed(error: str) -> None:
            self.duration_estimate_status.setObjectName("warningBox")
            self.duration_estimate_status.setText(self._(
                "Duration estimate unavailable: {error}. No body was read and no email was changed.",
                error=error,
            ))
            self._repolish(self.duration_estimate_status)

        def finished() -> None:
            self._tasks.discard(task)
            task.deleteLater()
            self._set_estimate_busy(False)

        task.succeeded.connect(succeeded)
        task.failed.connect(failed)
        task.finished.connect(finished)
        task.start()

    def _set_governor_operational_available(self, available: bool) -> None:
        self._governor_operational_available = available
        if not available and self.governor_enforced_checkbox.isChecked():
            previous = self.governor_enforced_checkbox.blockSignals(True)
            self.governor_enforced_checkbox.setChecked(False)
            self.governor_enforced_checkbox.blockSignals(previous)
        self.governor_enforced_checkbox.setEnabled(
            available and self._process is None and not self._schedule_busy
        )

    @staticmethod
    def _worker_model_arguments(account: AccountSettings) -> list[str]:
        spec = model_spec(account.model_profile)
        return [
            "--backend",
            spec.backend,
            "--ollama-model",
            spec.ollama_model,
        ]

    def _refresh_connection_status(self) -> None:
        if self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        is_gmail = account.provider is ProviderKind.GMAIL
        self.action_permission_button.setVisible(is_gmail)
        self.connect_button.setText(
            self._("Connect Gmail read-only") if is_gmail else self._("Connect Yahoo")
        )
        self.connection_explanation.setText(
            (
                self._("Step 1: select Google's Desktop OAuth file and authorise read-only Inbox access. Step 2: authorise actions separately only if you want to use Quarantine or Trash.")
            )
            if is_gmail
            else (
                self._("Create an app password in Yahoo Account Security, then enter it here. Your main account password is never requested.")
            )
        )
        if self.auth_service is None:
            self._connection_state = ConnectionState.ERROR
            self._connection_read_access = False
            self.connection_status.setObjectName("connectionOff")
            self.connection_status.setText(
                self.auth_error or self._("System credential manager unavailable")
            )
            for button in (
                self.connect_button,
                self.action_permission_button,
                self.test_connection_button,
                self.disconnect_button,
            ):
                button.setEnabled(False)
            self._repolish(self.connection_status)
            self._refresh_operation_availability()
            return
        try:
            status = self.auth_service.status(account.account_id, account.provider)
        except Exception as exc:
            self._connection_state = ConnectionState.ERROR
            self._connection_read_access = False
            self.connection_status.setObjectName("connectionOff")
            self.connection_status.setText(self._("Credential status unavailable: {error}", error=exc))
            self.test_connection_button.setEnabled(False)
            self.disconnect_button.setEnabled(False)
            self._repolish(self.connection_status)
            self._refresh_operation_availability()
            return
        object_name = {
            ConnectionState.READY: "connectionReady",
            ConnectionState.READ_ONLY: "connectionPartial",
            ConnectionState.NOT_CONFIGURED: "connectionOff",
            ConnectionState.ERROR: "connectionOff",
        }[status.state]
        self.connection_status.setObjectName(object_name)
        self.connection_status.setText(self._(status.detail))
        self._connection_state = status.state
        self._connection_read_access = status.read_access
        self.connect_button.setEnabled(True)
        self.action_permission_button.setEnabled(status.read_access)
        self.test_connection_button.setEnabled(status.read_access)
        self.disconnect_button.setEnabled(
            status.state is not ConnectionState.NOT_CONFIGURED
        )
        self._repolish(self.connection_status)
        self._refresh_operation_availability()
        self._refresh_safety_governor()

    @staticmethod
    def _repolish(widget: QWidget) -> None:
        widget.style().unpolish(widget)
        widget.style().polish(widget)

    def _set_mailbox_outcome(self, message: str, state: str) -> None:
        """Keep the header receipt consistent with the latest operation."""

        self.status_pill.setText(self._(message))
        self.status_pill.setProperty("outcomeState", state)
        self._repolish(self.status_pill)

    def _state_db(self, account: AccountSettings) -> Path:
        return state_database_path(
            self.store.path,
            self.project_root,
            account,
        )

    def _refresh_calibration_status(self) -> None:
        if self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        total = self._calibration_totals.get(account.account_id, 0)
        if self.auth_service is not None and self._connection_read_access:
            try:
                counts = calibration_answer_counts(
                    self._state_db(account),
                    account.account_id,
                    self.auth_service.store,
                )
                total = sum(counts.values())
                self._calibration_totals[account.account_id] = total
                self._calibration_ready[account.account_id] = (
                    total >= RECOMMENDED_INITIAL_QUIZ_ANSWERS
                    and counts.get("keep", 0) >= RECOMMENDED_INITIAL_KEEP_ANSWERS
                    and counts.get("dont_keep", 0)
                    >= RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS
                )
            except (OSError, RuntimeError, ValueError):
                total = self._calibration_totals.get(account.account_id, 0)
        ready = self._calibration_ready.get(account.account_id, False)
        if ready:
            self.quiz_button.setText(self._("Update quiz"))
            self.calibration_status.setObjectName("connectionReady")
            self.calibration_status.setText(self._(
                "Initial calibration complete · {total} answers for this account",
                total=total,
            ))
        else:
            self.quiz_button.setText(self._("Recommended onboarding quiz"))
            self.calibration_status.setObjectName("connectionPartial")
            self.calibration_status.setText(self._(
                "Recommended calibration: {total}/{target} answers · include at least {keep} Keep and {discard} Don't keep",
                total=total,
                target=RECOMMENDED_INITIAL_QUIZ_ANSWERS,
                keep=RECOMMENDED_INITIAL_KEEP_ANSWERS,
                discard=RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS,
            ))
        self._repolish(self.calibration_status)
        self._refresh_operation_availability()

    def _schedule_settings_from_controls(self, *, enabled: bool) -> ScheduleSettings:
        frequency = self.schedule_frequency.currentData()
        if not isinstance(frequency, ScheduleFrequency):
            frequency = ScheduleFrequency(str(frequency))
        weekday = self.schedule_weekday.currentData()
        if not isinstance(weekday, int):
            weekday = int(weekday)
        selected_time = self.schedule_time.time()
        return ScheduleSettings(
            enabled=enabled,
            hour=selected_time.hour(),
            minute=selected_time.minute(),
            frequency=frequency,
            weekday=weekday,
        )

    def _refresh_schedule_frequency_visibility(self) -> None:
        frequency = self.schedule_frequency.currentData()
        self.schedule_weekday.setVisible(frequency is ScheduleFrequency.WEEKLY)

    def _schedule_draft_changed(self, *_: Any) -> None:
        self._refresh_schedule_frequency_visibility()
        if self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        if account.schedule.enabled:
            self.schedule_status.setObjectName("connectionPartial")
            self.schedule_status.setText(self._(
                "Schedule changed: select Apply / update to update the native task."
            ))
            self._repolish(self.schedule_status)

    def _schedule_description(self, schedule: ScheduleSettings) -> str:
        time_text = f"{schedule.hour:02d}:{schedule.minute:02d}"
        if schedule.frequency is ScheduleFrequency.DAILY:
            return self._("every day at {time}", time=time_text)
        if schedule.frequency is ScheduleFrequency.WEEKDAYS:
            return self._("Monday to Friday at {time}", time=time_text)
        weekday = (
            self._("Monday").lower(),
            self._("Tuesday").lower(),
            self._("Wednesday").lower(),
            self._("Thursday").lower(),
            self._("Friday").lower(),
            self._("Saturday").lower(),
            self._("Sunday").lower(),
        )[schedule.weekday - 1]
        return self._("every {weekday} at {time}", weekday=weekday, time=time_text)

    def _refresh_schedule_status(self) -> None:
        if not hasattr(self, "schedule_status") or self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        if self.schedule_backend is None:
            self._native_schedule_installed = False
            self.schedule_status.setObjectName("connectionOff")
            self.schedule_status.setText(
                self.scheduler_error or self._("Native scheduling unavailable")
            )
            self._repolish(self.schedule_status)
            self._refresh_operation_availability()
            return
        try:
            status = self.schedule_backend.status(account.account_id)
        except (OSError, RuntimeError, ValueError) as exc:
            self._native_schedule_installed = False
            self.schedule_status.setObjectName("connectionPartial")
            self.schedule_status.setText(self._("Schedule status unavailable: {error}", error=exc))
            self._repolish(self.schedule_status)
            self._refresh_operation_availability()
            return
        self._native_schedule_installed = status.installed
        if status.installed and account.schedule.enabled:
            selected_model = self._(model_spec(account.model_profile).display_name)
            self.schedule_status.setObjectName("connectionReady")
            self.schedule_status.setText(self._(
                "{backend} active · {schedule} · {model} · one-shot run",
                backend=status.backend,
                schedule=self._schedule_description(account.schedule),
                model=selected_model,
            ))
        elif status.installed:
            self.schedule_status.setObjectName("connectionPartial")
            self.schedule_status.setText(self._(
                "A native task exists but is disabled in preferences. It will fail closed. Select Disable to remove it."
            ))
        elif account.schedule.enabled:
            self.schedule_status.setObjectName("connectionPartial")
            self.schedule_status.setText(self._(
                "The preference is enabled but the native task is missing. Apply it again or disable it."
            ))
        else:
            self.schedule_status.setObjectName("connectionOff")
            self.schedule_status.setText(self._("Inactive · {backend} backend", backend=status.backend))
        self._repolish(self.schedule_status)
        self._refresh_operation_availability()

    def _set_schedule_busy(self, busy: bool, message: str = "") -> None:
        self._schedule_busy = busy
        for control in (
            self.account_display_name,
            self.connect_button,
            self.action_permission_button,
            self.test_connection_button,
            self.disconnect_button,
            self.add_account_button,
            self.remove_account_button,
            self.save_button,
            self.discard_button,
            self.scan_button,
            self.quiz_button,
            self.review_quarantine_button,
            self.cancel_operation_button,
            self.unread_days,
            self.otp_days,
            self.scan_order,
            self.batch_size,
            self.quiz_size,
            self.model_profile,
            self.quarantine_radio,
            self.trash_radio,
            self.schedule_time,
            self.schedule_frequency,
            self.schedule_weekday,
            self.governor_enforced_checkbox,
            self.threat_protection_checkbox,
            self.threat_semantic_mode,
            self.lumegraph_checkbox,
            self.obsolescence_proof_checkbox,
            self.backtest_button,
            self.threat_backtest_button,
            self.duration_estimate_button,
            self.apply_schedule_button,
            self.remove_schedule_button,
            self.english_language_button,
            self.italian_language_button,
        ):
            control.setEnabled(not busy)
        if not busy:
            self._refresh_destination_capabilities()
            self._refresh_destination_notice()
        if busy:
            self.account_list.setEnabled(False)
            self.schedule_status.setObjectName("connectionPartial")
            self.schedule_status.setText(message)
            self._repolish(self.schedule_status)
        else:
            self.account_list.setEnabled(self._process is None)
            self._refresh_schedule_status()

    def _run_schedule_task(
        self,
        message: str,
        action: Callable[[], object],
        succeeded: Callable[[object], None],
    ) -> None:
        self._set_schedule_busy(True, message)
        task = BackgroundTask(action)
        self._tasks.add(task)

        def failed(error: str) -> None:
            QMessageBox.critical(
                self,
                self._("Schedule outcome requires review"),
                self._(
                    "The native task did not complete cleanly. InboxLume preferences were not changed; check Schedule status before retrying.\n\n{error}",
                    error=error,
                ),
            )

        def finished() -> None:
            self._tasks.discard(task)
            task.deleteLater()
            self._set_schedule_busy(False)

        task.succeeded.connect(succeeded)
        task.failed.connect(failed)
        task.finished.connect(finished)
        task.start()

    def _apply_schedule(self) -> None:
        if (
            self._process is not None
            or self._schedule_busy
            or self.current_account_id is None
            or self.schedule_backend is None
        ):
            return
        self._collect_form(self.current_account_id)
        account = self.settings.account(self.current_account_id)
        if not self._selected_model_is_ready():
            QMessageBox.warning(
                self,
                self._("Local model unavailable"),
                self._("Install the runtime and prepare the cache shown under Local AI model, then reopen InboxLume."),
            )
            return
        if self._connection_state is not ConnectionState.READY:
            QMessageBox.warning(
                self,
                self._("Account not ready"),
                self._("Scheduling requires Inbox read access and protected actions to be configured for this account."),
            )
            return
        if not self._calibration_ready.get(account.account_id, False):
            QMessageBox.warning(
                self,
                self._("Complete calibration first"),
                self._("An unattended scan requires at least 40 answers, including the minimum Keep and Don't keep counts. You can continue using Quarantine manually in the meantime."),
            )
            return
        draft = self._schedule_settings_from_controls(enabled=True)
        destination = (
            self._("Direct Trash")
            if account.destination is MessageDestination.TRASH
            else self._("Quarantine")
        )
        english_scope = (
            "all eligible, unprocessed email"
            if account.batch_size == 0
            else f"up to {account.batch_size} email"
        )
        warning = (
            f"InboxLume will check {english_scope} "
            f"{self._schedule_description(draft)}, sending safe suggestions to {destination}. "
            f"It will use {self._(model_spec(account.model_profile).display_name)}. "
            "The model will exit when finished and no process will remain resident.\n\n"
            "Choose a time when the computer is not under heavy load. Install the native task?"
        )
        if account.destination is MessageDestination.TRASH:
            retention = "30 days" if account.provider is ProviderKind.GMAIL else "7 days"
            warning += (
                f"\n\nWarning: the provider may automatically empty Trash after "
                f"{retention}. InboxLume cannot empty it."
            )
        if self.settings.language is UiLanguage.ITALIAN:
            italian_scope = (
                "tutte le email idonee non ancora elaborate"
                if account.batch_size == 0
                else f"fino a {account.batch_size} email"
            )
            warning = (
                f"InboxLume controllerà {italian_scope} "
                f"{self._schedule_description(draft)}, con destinazione {destination}. "
                f"Userà {self._(model_spec(account.model_profile).display_name)}. "
                "Il modello si chiuderà al termine e nessun processo resterà residente.\n\n"
                "Scegli un orario in cui il computer non è sotto sforzo. Installare l’attività nativa?"
            )
            if account.destination is MessageDestination.TRASH:
                retention = "30 giorni" if account.provider is ProviderKind.GMAIL else "7 giorni"
                warning += (
                    "\n\nAttenzione: il provider può svuotare automaticamente il "
                    f"Cestino dopo {retention}. InboxLume non può svuotarlo."
                )
        answer = QMessageBox.question(
            self,
            self._("Confirm schedule?"),
            warning,
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        scheduled_executable, packaged_worker = scheduled_worker_launch()
        request = ScheduleRequest(
            account.account_id,
            self.store.path.resolve(),
            scheduled_executable,
            draft,
            packaged_worker=packaged_worker,
        )

        def install() -> object:
            return self.schedule_backend.install(request)

        def installed(result: object) -> None:
            if not isinstance(result, ScheduleStatus) or not result.installed:
                QMessageBox.critical(
                    self,
                    self._("Schedule unchanged"),
                    self._("The native service did not confirm installation."),
                )
                return
            try:
                persisted_settings = self.store.load()
                in_memory_updated, persisted_updated = scoped_account_replacement(
                    self.settings,
                    persisted_settings,
                    account.account_id,
                    display_name=account.display_name,
                    unread_age_days=account.unread_age_days,
                    read_one_time_code_age_days=(
                        account.read_one_time_code_age_days
                    ),
                    scan_order=account.scan_order,
                    batch_size=account.batch_size,
                    quiz_size=account.quiz_size,
                    destination=account.destination,
                    model_profile=account.model_profile,
                    safety_governor_enforced=account.safety_governor_enforced,
                    threat_protection_enabled=account.threat_protection_enabled,
                    threat_semantic_mode=account.threat_semantic_mode,
                    lumegraph_enabled=account.lumegraph_enabled,
                    obsolescence_proof_enabled=account.obsolescence_proof_enabled,
                    schedule=draft,
                )
                self.store.save(persisted_updated)
            except (KeyError, OSError, ValueError) as exc:
                rollback_confirmed = False
                try:
                    rollback = self.schedule_backend.remove(account.account_id)
                    rollback_confirmed = (
                        isinstance(rollback, ScheduleStatus)
                        and not rollback.installed
                    )
                except (OSError, RuntimeError, ValueError):
                    pass
                QMessageBox.critical(
                    self,
                    self._("Preferences not saved"),
                    self._(
                        "The task was cancelled because preferences could not be saved.\n\n{error}"
                        if rollback_confirmed
                        else "Preferences could not be saved and removal of the native task was not confirmed. Check Schedule status before closing or retrying.\n\n{error}",
                        error=exc,
                    ),
                )
                return
            self.settings = in_memory_updated
            self.dirty = in_memory_updated != persisted_updated
            self.status_text.setText(
                self._("Schedule applied. The model does not remain loaded in memory.")
            )

        self._run_schedule_task(
            self._("Installing and checking the native task…"),
            install,
            installed,
        )

    def _remove_schedule(self) -> None:
        if (
            self._process is not None
            or self._schedule_busy
            or self.current_account_id is None
            or self.schedule_backend is None
        ):
            return
        account = self.settings.account(self.current_account_id)
        answer = QMessageBox.question(
            self,
            self._("Disable schedule?"),
            self._("Only this account's native task will be removed. Email, credentials, preferences, and history will not be deleted."),
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return

        def remove() -> object:
            return self.schedule_backend.remove(account.account_id)

        def removed(result: object) -> None:
            if not isinstance(result, ScheduleStatus) or result.installed:
                QMessageBox.critical(
                    self,
                    self._("Schedule unchanged"),
                    self._("The native service did not confirm removal."),
                )
                return
            disabled = ScheduleSettings(
                enabled=False,
                hour=account.schedule.hour,
                minute=account.schedule.minute,
                frequency=account.schedule.frequency,
                weekday=account.schedule.weekday,
            )
            try:
                updated, persisted = scoped_account_replacement(
                    self.settings,
                    self.store.load(),
                    account.account_id,
                    schedule=disabled,
                )
                self.store.save(persisted)
            except (KeyError, OSError, ValueError) as exc:
                QMessageBox.critical(
                    self,
                    self._("Preferences not saved"),
                    self._("The native task was removed, but preferences were not updated.\n\n{error}", error=exc),
                )
                return
            self.settings = updated
            self.dirty = updated != persisted
            self.status_text.setText(
                self._("Schedule removed; no email or credential changed.")
            )

        self._run_schedule_task(
            self._("Removing the native task…"),
            remove,
            removed,
        )

    def _refresh_operation_availability(self) -> None:
        if not hasattr(self, "scan_button"):
            return
        busy = self._process is not None or self._estimate_busy
        self.scan_button.setEnabled(
            not busy
            and not self._schedule_busy
            and self._connection_state is ConnectionState.READY
            and self._selected_model_is_ready()
        )
        self.quiz_button.setEnabled(
            not busy
            and not self._schedule_busy
            and self._connection_read_access
            and self._selected_model_is_ready()
        )
        self.review_quarantine_button.setEnabled(
            not busy
            and not self._schedule_busy
            and self._connection_read_access
            and self.auth_service is not None
        )
        self.cancel_operation_button.setEnabled(self._process is not None)
        self.add_account_button.setEnabled(not busy)
        self.remove_account_button.setEnabled(not busy)
        if hasattr(self, "apply_schedule_button"):
            account_id = self.current_account_id or ""
            self.apply_schedule_button.setEnabled(
                not busy
                and not self._schedule_busy
                and self.schedule_backend is not None
                and self._connection_state is ConnectionState.READY
                and self._calibration_ready.get(account_id, False)
                and self._selected_model_is_ready()
            )
            schedule_enabled = False
            if self.current_account_id is not None:
                schedule_enabled = self.settings.account(
                    self.current_account_id
                ).schedule.enabled
            self.remove_schedule_button.setEnabled(
                not busy
                and not self._schedule_busy
                and self.schedule_backend is not None
                and (self._native_schedule_installed or schedule_enabled)
            )
        if hasattr(self, "backtest_button"):
            self.backtest_button.setEnabled(
                not busy
                and not self._schedule_busy
                and self._connection_read_access
                and self.auth_service is not None
            )
        if hasattr(self, "threat_backtest_button"):
            self.threat_backtest_button.setEnabled(
                not busy
                and not self._schedule_busy
                and self._selected_model_is_ready()
            )
        if hasattr(self, "duration_estimate_button"):
            self.duration_estimate_button.setEnabled(
                not busy
                and not self._schedule_busy
                and self._connection_read_access
                and self.auth_service is not None
            )

    def _set_auth_busy(self, busy: bool, message: str = "") -> None:
        self.account_list.setEnabled(not busy)
        for button in (
            self.connect_button,
            self.action_permission_button,
            self.test_connection_button,
            self.disconnect_button,
            self.english_language_button,
            self.italian_language_button,
            self.backtest_button,
            self.threat_backtest_button,
            self.duration_estimate_button,
            self.review_quarantine_button,
        ):
            button.setEnabled(not busy)
        if busy:
            self.scan_button.setEnabled(False)
            self.quiz_button.setEnabled(False)
            self.review_quarantine_button.setEnabled(False)
            self.add_account_button.setEnabled(False)
            self.remove_account_button.setEnabled(False)
            self.apply_schedule_button.setEnabled(False)
            self.remove_schedule_button.setEnabled(False)
        if busy:
            self.connection_status.setObjectName("connectionPartial")
            self.connection_status.setText(message)
            self._repolish(self.connection_status)
        elif not busy:
            self._refresh_operation_availability()

    def _run_auth_task(
        self,
        message: str,
        action: Callable[[], object],
        success_text: str | None = None,
    ) -> None:
        self._set_auth_busy(True, message)
        task = BackgroundTask(action)
        self._tasks.add(task)

        def succeeded(result: object) -> None:
            self.status_text.setText(
                success_text or self._(str(result or "Operation complete."))
            )
            self._refresh_connection_status()
            self._refresh_calibration_status()

        def failed(error: str) -> None:
            self._refresh_connection_status()
            QMessageBox.critical(
                self,
                self._("Operation not completed"),
                self._("No email setting was changed.\n\n{error}", error=error),
            )

        def finished() -> None:
            self._tasks.discard(task)
            task.deleteLater()
            self._set_auth_busy(False)
            self._refresh_connection_status()
            self._refresh_calibration_status()

        task.succeeded.connect(succeeded)
        task.failed.connect(failed)
        task.finished.connect(finished)
        task.start()

    def _connect_account(self) -> None:
        if self.auth_service is None or self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        if account.provider is ProviderKind.GMAIL:
            path, _ = QFileDialog.getOpenFileName(
                self,
                self._("Choose Google's Desktop OAuth client"),
                str(Path.home()),
                self._("JSON files (*.json)"),
            )
            if not path:
                return
            self._run_auth_task(
                self._("Waiting for Gmail authorisation in the browser…"),
                lambda: self.auth_service.connect_gmail_readonly(
                    account.account_id,
                    Path(path),
                ),
                self._("Gmail connected with read-only access."),
            )
            return

        dialog = YahooCredentialsDialog(self.settings.language, self)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        email_address = dialog.email.text().strip()
        app_password = dialog.password.text()
        dialog.password.clear()
        self._run_auth_task(
            self._("Saving Yahoo credentials securely…"),
            lambda: self.auth_service.connect_yahoo(
                account.account_id,
                email_address,
                app_password,
            ),
            self._("Yahoo credentials saved in the system credential manager."),
        )

    def _connect_gmail_actions(self) -> None:
        if self.auth_service is None or self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        if account.provider is not ProviderKind.GMAIL:
            return
        self._run_auth_task(
            self._("Waiting for Gmail action authorisation in the browser…"),
            lambda: self.auth_service.connect_gmail_actions(account.account_id),
            self._("Gmail permission for Quarantine/Trash stored separately."),
        )

    def _test_connection(self) -> None:
        if self.auth_service is None or self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        self._run_auth_task(
            self._("Testing Inbox only, without reading message bodies…"),
            lambda: self.auth_service.test_connection(
                account.account_id,
                account.provider,
            ),
        )

    def _disconnect_account(self) -> None:
        if self.auth_service is None or self.current_account_id is None:
            return
        account = self.settings.account(self.current_account_id)
        if account.schedule.enabled or self._native_schedule_installed:
            QMessageBox.information(
                self,
                self._("Disable the schedule first"),
                self._("Disable this account's scheduled scan first to prevent runs without credentials."),
            )
            return
        provider_name = "Gmail" if account.provider is ProviderKind.GMAIL else "Yahoo"
        answer = QMessageBox.question(
            self,
            self._("Disconnect {provider}?", provider=provider_name),
            self._("Only this account's local credentials will be removed. Email and preferences will not be touched."),
            QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
            QMessageBox.StandardButton.Cancel,
        )
        if answer != QMessageBox.StandardButton.Yes:
            return
        try:
            removed = self.auth_service.disconnect(
                account.account_id,
                account.provider,
            )
        except Exception as exc:
            QMessageBox.critical(self, self._("Disconnect not completed"), str(exc))
            return
        self.status_text.setText(self._(
            "{provider} disconnected · {count} credentials removed",
            provider=provider_name,
            count=removed,
        ))
        self._refresh_connection_status()
        self._refresh_calibration_status()

    def _worker_common_arguments(
        self,
        command: str,
        account: AccountSettings,
    ) -> list[str]:
        return [
            "-m",
            "inboxlume.desktop_worker",
            command,
            "--config",
            str(self.config_path),
            "--account",
            account.account_id,
            "--provider",
            account.provider.value,
            "--state-db",
            str(self._state_db(account)),
            "--unread-days",
            str(account.unread_age_days),
            "--otp-days",
            str(account.read_one_time_code_age_days),
            "--confirm-read-bodies",
        ]

    def _start_scan(self) -> None:
        if (
            self._process is not None
            or self._estimate_busy
            or self.current_account_id is None
        ):
            return
        if not self.save():
            return
        account = self.settings.account(self.current_account_id)
        if not self._selected_model_is_ready():
            QMessageBox.warning(
                self,
                self._("Local model unavailable"),
                self._("The selected profile is not ready. Check its runtime and cache under Local AI model."),
            )
            return
        total = self._calibration_totals.get(account.account_id, 0)
        calibration_ready = self._calibration_ready.get(account.account_id, False)
        if account.destination is MessageDestination.TRASH and not calibration_ready:
            QMessageBox.warning(
                self,
                self._("Direct Trash is still locked"),
                self._("Complete at least 40 calibration answers, including examples to protect and examples not to keep. Use reversible Quarantine in the meantime."),
            )
            return
        if total < RECOMMENDED_INITIAL_QUIZ_ANSWERS:
            answer = QMessageBox.question(
                self,
                self._("Onboarding calibration incomplete"),
                self._(
                    "You have completed {total} of {target} answers. Completing the quiz first is strongly recommended. Run a Quarantine scan anyway?",
                    total=total,
                    target=RECOMMENDED_INITIAL_QUIZ_ANSWERS,
                ),
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        if account.destination is MessageDestination.TRASH:
            provider_retention = (
                "30 days" if account.provider is ProviderKind.GMAIL else "7 days"
            )
            if self.settings.language is UiLanguage.ITALIAN:
                provider_retention = (
                    "30 giorni" if account.provider is ProviderKind.GMAIL else "7 giorni"
                )
            answer = QMessageBox.warning(
                self,
                self._("Confirm Direct Trash?"),
                self._(
                    "Safe suggestions will skip Quarantine. The provider may automatically delete them after {retention}; InboxLume cannot empty Trash. Continue?",
                    retention=provider_retention,
                ),
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        arguments = self._worker_common_arguments("scan", account)
        arguments.extend(self._worker_model_arguments(account))
        arguments.extend(
            [
                "--limit",
                str(account.batch_size),
                "--search-limit",
                "0",
                "--scan-order",
                account.scan_order.value,
                "--destination",
                account.destination.value,
                "--apply-safe-actions",
            ]
        )
        if account.safety_governor_enforced:
            arguments.append("--enforce-safety-governor")
        if not account.threat_protection_enabled:
            arguments.append("--skip-threat-protection")
        else:
            arguments.extend(
                ["--threat-semantic-mode", account.threat_semantic_mode.value]
            )
        if not account.lumegraph_enabled:
            arguments.append("--skip-lumegraph")
        if not account.obsolescence_proof_enabled:
            arguments.append("--skip-obsolescence-proof")
        initial_message = (
            self._(
                "Starting {model} for every eligible, unprocessed email…",
                model=self._(model_spec(account.model_profile).display_name),
            )
            if account.batch_size == 0
            else self._(
                "Starting {model} for up to {count} email…",
                model=self._(model_spec(account.model_profile).display_name),
                count=account.batch_size,
            )
        )
        self._start_local_process(
            arguments,
            "scan",
            initial_message,
        )

    def _start_quiz(self) -> None:
        if (
            self._process is not None
            or self._estimate_busy
            or self.current_account_id is None
        ):
            return
        if not self.save():
            return
        account = self.settings.account(self.current_account_id)
        if not self._selected_model_is_ready():
            QMessageBox.warning(
                self,
                self._("Local model unavailable"),
                self._("The selected profile is not ready. Check its runtime and cache under Local AI model."),
            )
            return
        sample_limit = min(500, max(account.quiz_size * 2, 40))
        arguments = self._worker_common_arguments("quiz", account)
        arguments.extend(self._worker_model_arguments(account))
        arguments.extend(
            [
                "--limit",
                str(account.quiz_size),
                "--sample-limit",
                str(sample_limit),
            ]
        )
        dialog = QuizDialog(self.settings.language, self)
        dialog.answer_selected.connect(self._send_quiz_answer)
        dialog.stop_requested.connect(self._cancel_operation)
        dialog.finished.connect(
            lambda result, current=dialog: self._release_quiz_dialog(current)
        )
        self._quiz_dialog = dialog
        self._start_local_process(
            arguments,
            "quiz",
            self._("Preparing up to {count} different questions…", count=account.quiz_size),
        )
        dialog.show()

    def _start_shadow_review(self) -> None:
        """Ask only about prior local Quarantine proposals; no model is loaded."""

        if (
            self._process is not None
            or self._estimate_busy
            or self.current_account_id is None
        ):
            return
        if not self.save():
            return
        account = self.settings.account(self.current_account_id)
        arguments = self._worker_common_arguments("shadow-review", account)
        arguments.extend(self._worker_model_arguments(account))
        arguments.extend(
            [
                "--limit",
                str(account.quiz_size),
                "--search-limit",
                "500",
            ]
        )
        dialog = QuizDialog(self.settings.language, self, review_mode=True)
        dialog.answer_selected.connect(self._send_quiz_answer)
        dialog.stop_requested.connect(self._cancel_operation)
        dialog.finished.connect(
            lambda result, current=dialog: self._release_quiz_dialog(current)
        )
        self._quiz_dialog = dialog
        self._start_local_process(
            arguments,
            "shadow_review",
            self._("Preparing pending filter candidates…"),
        )
        dialog.show()

    def _start_threat_backtest(self) -> None:
        if (
            self._process is not None
            or self._estimate_busy
            or self.current_account_id is None
        ):
            return
        if not self.save():
            return
        account = self.settings.account(self.current_account_id)
        if not self._selected_model_is_ready():
            QMessageBox.warning(
                self,
                self._("Local model unavailable"),
                self._("The selected profile is not ready. Check its runtime and cache under Local AI model."),
            )
            return
        arguments = [
            "-m",
            "inboxlume.desktop_worker",
            "threat-backtest",
            *self._worker_model_arguments(account),
        ]
        self._start_local_process(
            arguments,
            "threat_backtest",
            self._(
                "Starting {model} on the packaged synthetic threat corpus… No email account will be accessed.",
                model=self._(model_spec(account.model_profile).display_name),
            ),
        )

    def _release_quiz_dialog(self, dialog: QuizDialog) -> None:
        if self._quiz_dialog is dialog:
            self._quiz_dialog = None
        dialog.deleteLater()

    def _start_local_process(
        self,
        arguments: list[str],
        operation: str,
        initial_message: str,
    ) -> None:
        process = QProcess(self)
        process.setWorkingDirectory(str(self.project_root))
        environment = QProcessEnvironment.systemEnvironment()
        environment.insert("HF_HUB_OFFLINE", "1")
        environment.insert("TRANSFORMERS_OFFLINE", "1")
        process.setProcessEnvironment(environment)
        process.readyReadStandardOutput.connect(self._consume_process_output)
        process.readyReadStandardError.connect(self._consume_process_error)
        process.finished.connect(self._process_finished)
        process.errorOccurred.connect(self._process_error)
        self._process = process
        self._process_buffer = ""
        self._operation = operation
        self._terminal_event_received = False
        self._set_operation_busy(True)
        if operation == "scan":
            self._set_mailbox_outcome("Scan in progress", "active")
        else:
            self._set_mailbox_outcome("No email changed", "safe")
        self.operation_progress.setRange(0, 0)
        self.operation_progress.setFormat(self._("Starting…"))
        self.operation_summary.setText(initial_message)
        launch = desktop_worker_launch(arguments)
        process.start(str(launch.program), list(launch.arguments))

    def _set_operation_busy(self, busy: bool) -> None:
        self.account_list.setEnabled(not busy)
        for control in (
            self.connect_button,
            self.action_permission_button,
            self.test_connection_button,
            self.disconnect_button,
            self.add_account_button,
            self.remove_account_button,
            self.save_button,
            self.discard_button,
            self.unread_days,
            self.otp_days,
            self.scan_order,
            self.batch_size,
            self.quiz_size,
            self.model_profile,
            self.quarantine_radio,
            self.trash_radio,
            self.governor_enforced_checkbox,
            self.threat_protection_checkbox,
            self.threat_semantic_mode,
            self.lumegraph_checkbox,
            self.obsolescence_proof_checkbox,
            self.backtest_button,
            self.threat_backtest_button,
            self.duration_estimate_button,
            self.review_quarantine_button,
            self.schedule_time,
            self.schedule_frequency,
            self.schedule_weekday,
            self.apply_schedule_button,
            self.remove_schedule_button,
            self.english_language_button,
            self.italian_language_button,
        ):
            control.setEnabled(not busy)
        if not busy:
            self._refresh_destination_capabilities()
            self._refresh_destination_notice()
        self._refresh_operation_availability()

    def _consume_process_output(self) -> None:
        if self._process is None:
            return
        chunk = bytes(self._process.readAllStandardOutput()).decode(
            "utf-8", errors="replace"
        )
        self._process_buffer += chunk
        while "\n" in self._process_buffer:
            line, self._process_buffer = self._process_buffer.split("\n", 1)
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(event, dict):
                self._handle_worker_event(event)

    def _consume_process_error(self) -> None:
        if self._process is not None:
            self._process.readAllStandardError()

    def _handle_worker_event(self, event: dict[str, Any]) -> None:
        event_type = event.get("type")
        if event_type == "phase":
            self.operation_progress.setRange(0, 0)
            message = str(event.get("message") or "In progress…")
            self.operation_progress.setFormat(self._(message))
            self.operation_summary.setText(self._(message))
        elif event_type == "progress":
            processed = int(event.get("processed", 0))
            limit = int(event.get("limit", 1))
            if limit == 0:
                self.operation_progress.setRange(0, 0)
                self.operation_progress.setFormat(self._(
                    "{processed} analysed · continuing until no eligible email remains",
                    processed=processed,
                ))
            else:
                limit = max(1, limit)
                self.operation_progress.setRange(0, limit)
                self.operation_progress.setValue(processed)
                self.operation_progress.setFormat(self._(
                    "{processed} / {limit} analysed", processed=processed, limit=limit
                ))
        elif event_type == "candidate":
            if self._quiz_dialog is not None:
                self._quiz_dialog.show_candidate(event)
            self.operation_summary.setText(self._(
                "Quiz in progress: decide from this message's specific content."
            ))
        elif event_type == "summary":
            self._terminal_event_received = True
            if self._operation == "shadow_review":
                validation = (
                    event.get("validation")
                    if isinstance(event.get("validation"), dict)
                    else {}
                )
                conclusive = int(validation.get("keep", 0)) + int(
                    validation.get("dont_keep", 0)
                )
                if self._quiz_dialog is not None:
                    self._quiz_dialog.show_summary(event)
                self.operation_progress.setRange(0, 100)
                self.operation_progress.setValue(100)
                self.operation_progress.setFormat(
                    self._("Filter review complete")
                )
                self.operation_summary.setText(self._(
                    "{presented} filter candidates reviewed · {conclusive} conclusive overall",
                    presented=int(event.get("presented", 0)),
                    conclusive=conclusive,
                ))
                return
            total = int(event.get("calibration_total", 0))
            if self.current_account_id is not None:
                self._calibration_totals[self.current_account_id] = total
                raw_counts = event.get("calibration_counts")
                counts = raw_counts if isinstance(raw_counts, dict) else {}
                self._calibration_ready[self.current_account_id] = (
                    total >= RECOMMENDED_INITIAL_QUIZ_ANSWERS
                    and int(counts.get("keep", 0))
                    >= RECOMMENDED_INITIAL_KEEP_ANSWERS
                    and int(counts.get("dont_keep", 0))
                    >= RECOMMENDED_INITIAL_DONT_KEEP_ANSWERS
                )
            if self._quiz_dialog is not None:
                self._quiz_dialog.show_summary(event)
            self.operation_progress.setRange(0, 100)
            self.operation_progress.setValue(100)
            self.operation_progress.setFormat(self._("Quiz complete"))
            self.operation_summary.setText(self._(
                "{presented} new answers · {total}/{target} overall",
                presented=int(event.get("presented", 0)),
                total=total,
                target=RECOMMENDED_INITIAL_QUIZ_ANSWERS,
            ))
        elif event_type == "shadow_run_summary":
            self._terminal_event_received = True
            newly = int(event.get("newly_processed", 0))
            ledger = event.get("ledger") if isinstance(event.get("ledger"), dict) else {}
            total = int(ledger.get("processed_total", newly))
            automatic = (
                event.get("automatic_quarantine")
                if isinstance(event.get("automatic_quarantine"), dict)
                else {}
            )
            applied = int(automatic.get("applied", 0))
            if event.get("changes_mailbox") is True or applied > 0:
                self._set_mailbox_outcome(
                    "Mailbox actions completed", "changed"
                )
            else:
                self._set_mailbox_outcome("No email changed", "safe")
            governor = (
                event.get("safety_governor")
                if isinstance(event.get("safety_governor"), dict)
                else {}
            )
            blocked = int(governor.get("blocked_current_batch", 0))
            destination = (
                self._("Direct Trash")
                if automatic.get("destination") == "trash"
                else self._("Quarantine")
            )
            self.operation_progress.setRange(0, 100)
            self.operation_progress.setValue(100)
            self.operation_progress.setFormat(self._("Scan complete"))
            self.operation_summary.setText(self._(
                "{newly} new email analysed · {applied} moved to {destination} · {blocked} blocked by Safety Governor · {total} recorded overall",
                newly=newly,
                applied=applied,
                destination=destination,
                blocked=blocked,
                total=total,
            ))
            threat = (
                event.get("threat_protection")
                if isinstance(event.get("threat_protection"), dict)
                else {}
            )
            assessed_threat = int(threat.get("assessed_current_batch", 0))
            protected_threat = int(
                threat.get("protective_reviews_current_batch", 0)
            )
            semantic_failures = int(
                threat.get("semantic_failures_current_batch", 0)
            )
            semantic_requested = int(
                threat.get("semantic_inferences_requested_current_batch", 0)
            )
            semantic_skipped = int(
                threat.get("semantic_inferences_skipped_current_batch", 0)
            )
            threat_ledger = (
                threat.get("ledger")
                if isinstance(threat.get("ledger"), dict)
                else {}
            )
            threat_marker = (
                event.get("threat_marker")
                if isinstance(event.get("threat_marker"), dict)
                else {}
            )
            marker_visible = int(threat_marker.get("visible", 0))
            marker_failed = int(
                (threat_marker.get("outcomes") or {}).get("failed", 0)
                if isinstance(threat_marker.get("outcomes"), dict)
                else 0
            )
            self.threat_status.setObjectName(
                "warningBox"
                if protected_threat > 0 or semantic_failures > 0 or marker_failed > 0
                else "safeBox"
                if assessed_threat > 0
                else "fieldHint"
            )
            threat_text = self._(
                "Local Threat Protection · {assessed} assessed in this batch · {protected} high-risk messages protected · {semantic} targeted local AI follow-ups · {skipped} technical-clear messages skipped · {fallbacks} semantic fallbacks · {total} private assessments overall. It never authorises cleanup.",
                assessed=assessed_threat,
                protected=protected_threat,
                semantic=semantic_requested,
                skipped=semantic_skipped,
                fallbacks=semantic_failures,
                total=int(threat_ledger.get("assessed_total", assessed_threat)),
            )
            if threat_marker.get("kind") == "gmail_label":
                threat_text += "\n" + self._(
                    "Gmail phishing label · {visible} high-risk messages labelled InboxLume/Sospetto phishing and kept in Inbox with other labels preserved · {failed} label failures.",
                    visible=marker_visible,
                    failed=marker_failed,
                )
            elif threat_marker.get("kind") == "yahoo_star":
                threat_text += "\n" + self._(
                    "Yahoo phishing flag · {visible} high-risk messages marked with \\Flagged and kept in Inbox with existing flags preserved; the star is not exclusive to InboxLume · {failed} flag failures.",
                    visible=marker_visible,
                    failed=marker_failed,
                )
            self.threat_status.setText(threat_text)
            self._repolish(self.threat_status)
            lumegraph = (
                event.get("lumegraph")
                if isinstance(event.get("lumegraph"), dict)
                else {}
            )
            if lumegraph.get("available") is False:
                self.lumegraph_status.setObjectName("warningBox")
                self.lumegraph_status.setText(self._(
                    "LumeGraph was unavailable for this batch. The ordinary filter completed unchanged and no graph-based action was authorised."
                ))
            else:
                graph_ledger = (
                    lumegraph.get("ledger")
                    if isinstance(lumegraph.get("ledger"), dict)
                    else {}
                )
                self.lumegraph_status.setObjectName("safeBox")
                self.lumegraph_status.setText(self._(
                    "LumeGraph active · {new_nodes} new utility nodes · {new_transitions} new transitions · {nodes} nodes overall · policy effects require verified closure proofs.",
                    new_nodes=int(lumegraph.get("run_nodes", 0)),
                    new_transitions=int(lumegraph.get("run_transitions", 0)),
                    nodes=int(graph_ledger.get("nodes_total", 0)),
                ))
            self._repolish(self.lumegraph_status)
            proof = (
                event.get("proof_of_obsolescence")
                if isinstance(event.get("proof_of_obsolescence"), dict)
                else {}
            )
            self.proof_status.setObjectName(
                "safeBox" if int(proof.get("verified_current_batch", 0)) else "fieldHint"
            )
            self.proof_status.setText(self._(
                "Proof of Obsolescence · {verified} verified in this batch · {promoted} promoted to Quarantine · {withheld} intentionally not promoted to Direct Trash.",
                verified=int(proof.get("verified_current_batch", 0)),
                promoted=int(proof.get("promoted_to_quarantine_current_batch", 0)),
                withheld=int(proof.get("withheld_from_direct_trash_current_batch", 0)),
            ))
            self._repolish(self.proof_status)
            self.status_text.setText(self._(
                "Scan finished. No body or subject was stored in plaintext."
            ))
            elapsed = event.get("elapsed_seconds")
            if (
                newly > 0
                and isinstance(elapsed, (int, float))
                and not isinstance(elapsed, bool)
                and float(elapsed) > 0
                and self.current_account_id is not None
                and self.auth_service is not None
            ):
                try:
                    account = self.settings.account(self.current_account_id)
                    record_local_scan_timing(
                        self._state_db(account),
                        account,
                        self.auth_service.store,
                        self.hardware,
                        newly,
                        float(elapsed),
                        recorded_at=datetime.now(timezone.utc),
                    )
                except (OSError, RuntimeError, ValueError):
                    # Timing telemetry is optional and local; a completed scan
                    # must never be reported as failed because of it.
                    pass
        elif event_type == "local_threat_backtest":
            self._terminal_event_received = True
            cases = event.get("cases") if isinstance(event.get("cases"), dict) else {}
            outcomes = (
                event.get("outcomes")
                if isinstance(event.get("outcomes"), dict)
                else {}
            )
            metrics = (
                event.get("metrics")
                if isinstance(event.get("metrics"), dict)
                else {}
            )
            total = int(cases.get("total", 0))
            benign = int(cases.get("benign", 0))
            false_positive = int(outcomes.get("false_protective_reviews", 0))
            failures = int(outcomes.get("model_failures", 0))
            precision = metrics.get("precision")
            precision_percent = (
                0.0
                if not isinstance(precision, (int, float)) or isinstance(precision, bool)
                else 100.0 * float(precision)
            )
            recall = metrics.get("recall")
            recall_percent = (
                0.0
                if not isinstance(recall, (int, float)) or isinstance(recall, bool)
                else 100.0 * float(recall)
            )
            upper = metrics.get("false_positive_upper_95")
            upper_percent = (
                100.0
                if not isinstance(upper, (int, float)) or isinstance(upper, bool)
                else 100.0 * float(upper)
            )
            passed = event.get("diagnostic_passed") is True
            result_text = (
                self._("preliminary targets met")
                if passed
                else self._("preliminary targets not met")
            )
            self.operation_progress.setRange(0, 100)
            self.operation_progress.setValue(100)
            self.operation_progress.setFormat(self._("Threat backtest complete"))
            self.operation_summary.setText(self._(
                "Synthetic threat backtest complete. No email account was accessed and the model was unloaded."
            ))
            self.threat_backtest_status.setObjectName(
                "safeBox" if passed else "warningBox"
            )
            self.threat_backtest_status.setText(self._(
                "Synthetic threat backtest · {result} · {cases} cases · precision {precision}% · recall {recall}% · false positives {false_positive}/{benign} (95% upper bound {upper}%) · model failures {failures}. This diagnostic never authorises mailbox actions.",
                result=result_text,
                cases=total,
                precision=f"{precision_percent:.1f}",
                recall=f"{recall_percent:.1f}",
                false_positive=false_positive,
                benign=benign,
                upper=f"{upper_percent:.1f}",
                failures=failures,
            ))
            self._repolish(self.threat_backtest_status)
        elif event_type == "error":
            self._terminal_event_received = True
            safe_error = self._(
                str(event.get("message") or "Local process error")
            )
            if self._operation == "threat_backtest":
                self.threat_backtest_status.setObjectName("warningBox")
                self.threat_backtest_status.setText(self._(
                    "Synthetic threat backtest did not complete: {error}. No email account was accessed.",
                    error=safe_error,
                ))
                self._repolish(self.threat_backtest_status)
            if self._quiz_dialog is not None:
                self._quiz_dialog.running = False
                self._quiz_dialog.close()
            self.operation_progress.setRange(0, 100)
            self.operation_progress.setValue(0)
            self.operation_progress.setFormat(self._("Not completed"))
            error_message = safe_error
            mailbox_outcome = event.get("mailbox_outcome")
            outcome_unknown = (
                mailbox_outcome == "unknown"
                or event.get("mailbox_changes_unknown") is True
            )
            outcome_unchanged = mailbox_outcome == "unchanged"
            if self._operation == "scan" and outcome_unknown:
                error_message += "\n\n" + self._(
                    "The scan stopped before its final receipt. Some reversible actions may already have completed; refresh the provider mailbox and review Quarantine or Trash before retrying."
                )
                self.operation_summary.setText(self._(
                    "Scan not completed · mailbox outcome requires review."
                ))
                self._set_mailbox_outcome("Outcome to verify", "warning")
            elif self._operation == "scan" and outcome_unchanged:
                self.operation_summary.setText(self._(
                    "Scan not completed · no mailbox action started."
                ))
                self._set_mailbox_outcome("No email changed", "safe")
            elif self._operation == "scan":
                # Legacy or malformed failure receipts cannot prove where the
                # worker stopped, so retain the conservative outcome.
                error_message += "\n\n" + self._(
                    "The scan stopped before its final receipt. Some reversible actions may already have completed; refresh the provider mailbox and review Quarantine or Trash before retrying."
                )
                self.operation_summary.setText(self._(
                    "Scan not completed · mailbox outcome requires review."
                ))
                self._set_mailbox_outcome("Outcome to verify", "warning")
            else:
                self._set_mailbox_outcome("No email changed", "safe")
            QMessageBox.critical(
                self,
                self._("Operation not completed"),
                error_message,
            )
        elif event_type == "cancelled":
            self._terminal_event_received = True
            mailbox_outcome = event.get("mailbox_outcome")
            if (
                self._operation == "scan"
                and (
                    mailbox_outcome == "unknown"
                    or event.get("mailbox_changes_unknown") is True
                )
            ):
                self.operation_summary.setText(self._(
                    "Scan stopped · some reversible actions may already have completed; review the mailbox before retrying."
                ))
                self._set_mailbox_outcome("Outcome to verify", "warning")
            elif self._operation == "scan" and mailbox_outcome == "unchanged":
                self.operation_summary.setText(self._(
                    "Scan stopped before mailbox actions started."
                ))
                self._set_mailbox_outcome("No email changed", "safe")
            else:
                self.operation_summary.setText(self._(
                    "Operation stopped. Answers already given remain saved."
                ))
                self._set_mailbox_outcome("No email changed", "safe")

    def _send_quiz_answer(self, answer: str) -> None:
        if self._process is None or self._operation not in {"quiz", "shadow_review"}:
            return
        payload = json.dumps({"answer": answer}, separators=(",", ":")) + "\n"
        self._process.write(payload.encode("utf-8"))

    def _cancel_operation(self) -> None:
        if self._process is None:
            return
        self.operation_summary.setText(self._("Stopping the local process…"))
        process = self._process
        self._signal_process_tree(process, force=False)
        QTimer.singleShot(3_000, lambda: self._force_stop_process(process))

    @staticmethod
    def _signal_process_tree(process: QProcess, *, force: bool) -> None:
        process_id = int(process.processId())
        signalled = terminate_process_tree(process_id, force=force)
        if not signalled:
            process.kill() if force else process.terminate()

    def _force_stop_process(self, process: QProcess) -> None:
        if (
            self._process is process
            and process.state() != QProcess.ProcessState.NotRunning
        ):
            self._signal_process_tree(process, force=True)

    def _process_error(self, error: QProcess.ProcessError) -> None:
        if self._process is None:
            return
        self.operation_summary.setText(self._("Could not start the local process."))
        if error is QProcess.ProcessError.FailedToStart:
            if self._quiz_dialog is not None:
                self._quiz_dialog.running = False
                self._quiz_dialog.close()
            process = self._process
            self._process = None
            self._operation = None
            process.deleteLater()
            self._set_operation_busy(False)
            self._refresh_connection_status()
            self._set_mailbox_outcome("No email changed", "safe")
            QMessageBox.critical(
                self,
                self._("Local worker did not start"),
                self._("Check the InboxLume desktop installation and try again."),
            )

    def _process_finished(self, exit_code: int, _: QProcess.ExitStatus) -> None:
        process = self._process
        if process is None:
            return
        operation = self._operation
        self._consume_process_output()
        if not self._terminal_event_received and exit_code != 130:
            if operation == "scan":
                detail = self._(
                    "The local process stopped unexpectedly (exit code {code}). Its final receipt is unavailable, so some reversible actions may already have completed. Review Quarantine or Trash before retrying. Permanent deletion is not available in InboxLume.",
                    code=exit_code,
                )
                self.operation_summary.setText(self._(
                    "Scan not completed · mailbox outcome requires review."
                ))
                self._set_mailbox_outcome("Outcome to verify", "warning")
            else:
                detail = self._(
                    "The local process stopped unexpectedly (exit code {code}). This operation cannot change email.",
                    code=exit_code,
                )
                self._set_mailbox_outcome("No email changed", "safe")
            QMessageBox.critical(
                self,
                self._("Local process interrupted"),
                detail,
            )
        if self._quiz_dialog is not None and exit_code == 130:
            self._quiz_dialog.running = False
            self._quiz_dialog.close()
        self._process = None
        self._operation = None
        process.deleteLater()
        self._set_operation_busy(False)
        self._refresh_connection_status()
        self._refresh_calibration_status()
        self._refresh_threat_status()
        self._refresh_safety_governor()

    def _mark_dirty(self, *_: Any) -> None:
        self.dirty = True
        self.status_text.setText(self._("Unsaved changes."))

    def _optional_module_changed(self, *_: Any) -> None:
        self.threat_semantic_mode.setEnabled(
            self.threat_protection_checkbox.isChecked()
            and self._process is None
            and not self._schedule_busy
            and not self._estimate_busy
        )
        self._refresh_threat_status()
        self._refresh_lumegraph_status()
        self._reset_duration_estimate()
        self._mark_dirty()

    def _threat_semantic_mode_changed(self, *_: Any) -> None:
        self._refresh_threat_status()
        self._reset_duration_estimate()
        self._mark_dirty()

    def _display_name_changed(self, text: str) -> None:
        if self.current_account_id is not None:
            account = self.settings.account(self.current_account_id)
            provider_name = (
                "Gmail" if account.provider is ProviderKind.GMAIL else "Yahoo"
            )
            self.page_title.setText(
                text.strip()
                or self._("Rules for {provider}", provider=provider_name)
            )
        self._mark_dirty()

    def _refresh_account_list_labels(self) -> None:
        for row in range(self.account_list.count()):
            item = self.account_list.item(row)
            account_id = item.data(Qt.ItemDataRole.UserRole)
            try:
                account = self.settings.account(str(account_id))
            except KeyError:
                continue
            provider_name = (
                "Gmail" if account.provider is ProviderKind.GMAIL else "Yahoo"
            )
            item.setText(
                f"  {account.display_name or provider_name}\n  {provider_name}"
            )

    def _destination_changed(self, *_: Any) -> None:
        self._refresh_destination_notice()
        self._reset_duration_estimate()
        self._mark_dirty()

    def _refresh_destination_capabilities(self) -> None:
        if not hasattr(self, "trash_radio"):
            return
        busy = self._process is not None or self._schedule_busy or self._estimate_busy
        model_allows_trash = model_spec(
            self._selected_model_profile()
        ).direct_trash_allowed
        self.quarantine_radio.setEnabled(not busy)
        self.trash_radio.setEnabled(
            not busy
            and model_allows_trash
        )

    def _refresh_destination_notice(self) -> None:
        if self.current_account_id is None:
            return
        self.governor_enforced_checkbox.setEnabled(
            self._governor_operational_available
            and self._process is None
            and not self._schedule_busy
        )
        self._refresh_destination_capabilities()
        provider = self.settings.account(self.current_account_id).provider
        if self.trash_radio.isChecked():
            self.destination_notice.setObjectName("warningBox")
            retention = "30 days" if provider is ProviderKind.GMAIL else "7 days"
            if self.settings.language is UiLanguage.ITALIAN:
                retention = "30 giorni" if provider is ProviderKind.GMAIL else "7 giorni"
            if self.governor_enforced_checkbox.isChecked():
                if self._governor_trash_ready:
                    message = "Direct Trash remains available under the ordinary safeguards. Strictly qualified families also receive Safety Governor authorisation. Review Trash in your email provider and empty it manually only when satisfied. The provider may also delete messages after {retention}."
                else:
                    message = "Direct Trash remains available under the ordinary safeguards. The Safety Governor is not yet qualified for Trash and has no authority over these moves. Review Trash in your email provider and empty it manually only when satisfied. The provider may also delete messages after {retention}."
            else:
                message = "Direct Trash skips Quarantine using the selected model, calibration and policy safeguards; the Safety Governor is not active. Review Trash in your email provider and empty it manually only when satisfied. The provider may also delete messages after {retention}."
            self.destination_notice.setText(self._(message, retention=retention))
        else:
            self.destination_notice.setObjectName("safeBox")
            self.destination_notice.setText(self._(
                "Safe suggestions remain recoverable in the custom Quarantine. Review them in your email provider, then move the selected messages to Trash manually when satisfied."
            ))
        self.destination_notice.style().unpolish(self.destination_notice)
        self.destination_notice.style().polish(self.destination_notice)

    @staticmethod
    def _scheduled_runtime_fingerprint(account: AccountSettings) -> tuple[object, ...]:
        return (
            account.unread_age_days,
            account.read_one_time_code_age_days,
            account.scan_order,
            account.batch_size,
            account.destination,
            account.model_profile,
            account.safety_governor_enforced,
            account.threat_protection_enabled,
            account.threat_semantic_mode,
            account.lumegraph_enabled,
            account.obsolescence_proof_enabled,
        )

    def save(self, checked: bool = False) -> bool:  # noqa: ARG002
        if self.current_account_id is not None:
            self._collect_form(self.current_account_id)
        try:
            persisted = self.store.load()
            changed_scheduled_accounts: list[str] = []
            for previous in persisted.accounts:
                if not previous.schedule.enabled:
                    continue
                try:
                    candidate = self.settings.account(previous.account_id)
                except KeyError:
                    continue
                if self._scheduled_runtime_fingerprint(
                    previous
                ) != self._scheduled_runtime_fingerprint(candidate):
                    changed_scheduled_accounts.append(
                        candidate.display_name or candidate.account_id
                    )
            if changed_scheduled_accounts:
                QMessageBox.information(
                    self,
                    self._("Update the schedule too"),
                    self._(
                        "These changes affect an existing scheduled scan: {accounts}. Use Apply / update under Schedule so InboxLume can show the destination and limits again before saving.",
                        accounts=", ".join(changed_scheduled_accounts),
                    ),
                )
                return False
            self.store.save(self.settings)
        except (KeyError, OSError, ValueError) as exc:
            QMessageBox.critical(
                self,
                self._("Preferences not saved"),
                self._("InboxLume did not change preferences.\n\n{error}", error=exc),
            )
            return False
        self.dirty = False
        self._refresh_account_list_labels()
        self.status_text.setText(self._("Preferences saved to {path}", path=self.store.path))
        self.settings_saved.emit(str(self.store.path))
        return True

    def discard_changes(self) -> None:
        try:
            self.settings = self.store.load()
        except ValueError as exc:
            QMessageBox.critical(self, self._("Preferences could not be read"), str(exc))
            return
        self.dirty = False
        if self.current_account_id is not None:
            self._load_form(self.settings.account(self.current_account_id))
        self.status_text.setText(self._("Changes discarded."))

    def closeEvent(self, event: QCloseEvent) -> None:  # noqa: N802
        if self._estimate_busy or self._schedule_busy:
            QMessageBox.information(
                self,
                self._("Local task in progress"),
                self._(
                    "Wait for the local estimate or native schedule update to finish before closing InboxLume."
                ),
            )
            event.ignore()
            return
        if self._process is not None:
            answer = QMessageBox.question(
                self,
                self._("Stop the operation?"),
                self._("The local model is still running. Quiz answers already given will remain saved."),
                QMessageBox.StandardButton.Cancel | QMessageBox.StandardButton.Yes,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                event.ignore()
                return
            self._signal_process_tree(self._process, force=False)
            if not self._process.waitForFinished(3_000):
                self._signal_process_tree(self._process, force=True)
                self._process.waitForFinished(1_000)
        if not self.dirty:
            event.accept()
            return
        answer = QMessageBox.question(
            self,
            self._("Save changes?"),
            self._("Preferences have changed. Save them before closing?"),
            QMessageBox.StandardButton.Save
            | QMessageBox.StandardButton.Discard
            | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Save,
        )
        if answer == QMessageBox.StandardButton.Save:
            self.save()
            event.accept() if not self.dirty else event.ignore()
        elif answer == QMessageBox.StandardButton.Discard:
            event.accept()
        else:
            event.ignore()


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("InboxLume")
    app.setOrganizationName("InboxLume")
    app.setFont(QFont("", 10))
    configure_application_appearance(app)
    window = SettingsWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
