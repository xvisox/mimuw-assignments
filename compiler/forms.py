from django import forms
from django.core.exceptions import ValidationError

from compiler.models import Section


class CreateDirectoryForm(forms.Form):
    name = forms.CharField(max_length=20)
    description = forms.CharField(max_length=100, required=False)
    parent = forms.IntegerField(min_value=-1, required=False)  # (-1, '', None) mean root directory

    description.widget.attrs.update({"class": "form-control", "placeholder": "Description (optional)"})
    name.widget.attrs.update({"class": "form-control", "placeholder": "Directory name"})
    parent.widget = parent.hidden_widget()


class UploadFileForm(forms.Form):
    description = forms.CharField(max_length=100, required=False)
    parent = forms.IntegerField(min_value=0, required=True)  # we want to know where to put the file
    file = forms.FileField()

    # add extra validation for file extension
    def clean_file(self):
        uploaded_file = self.cleaned_data.get('file')
        if uploaded_file:
            file_extension = uploaded_file.name.split('.')[-1].lower()
            if file_extension not in ['h', 'c', 'cc']:
                raise ValidationError('Invalid file type. Only .h, .c and .cc are allowed.')
        return uploaded_file

    description.widget.attrs.update({"class": "form-control", "placeholder": "Description (optional)"})
    file.widget.attrs.update({"class": "form-control"})
    parent.widget = parent.hidden_widget()


class ChangeSectionsForm(forms.Form):
    sectionType = forms.ChoiceField(choices=Section.SectionType.choices)
    start = forms.IntegerField()
    end = forms.IntegerField()

    # check if start < end
    def clean(self):
        cleaned_data = super().clean()
        start = cleaned_data.get("start")
        end = cleaned_data.get("end")
        if start and end:
            if start > end:
                raise ValidationError("Start row must be lower than end row.")

    start.widget = start.hidden_widget()
    end.widget = end.hidden_widget()
    sectionType.widget.attrs.update({"class": "form-control h-100"})


class CompileForm(forms.Form):
    # this form will always be valid because of the default values
    BLANK_CHOICE = ("Default", "Select an option...")
    BLANK_CHOICE_MCS51 = ("Default", "Select an option for MCS51...")
    BLANK_CHOICE_Z80 = ("Default", "Select an option for Z80...")
    BLANK_CHOICE_STM8 = ("Default", "Select an option for STM8...")

    standard = forms.ChoiceField(
        choices=[
            BLANK_CHOICE,
            ("--std-c89", "C89"),
            ("--std-c99", "C99"),
            ("--std-c11", "C11")
        ], required=False)

    optimization = forms.MultipleChoiceField(
        choices=[
            ("--nolabelopt", "Will not optimize labels (makes the dumpfiles more readable)."),
            ("--noloopreverse", "Will not do loop reversal optimization."),
            ("--no-peep", "Disable peep-hole optimization with built-in rules."),
            ("--opt-code-speed", "The compiler will optimize code generation towards fast code.")
        ], required=False)

    processor = forms.ChoiceField(
        choices=[
            BLANK_CHOICE,
            ("-mmcs51", "MCS51"),
            ("-mz80", "Z80"),
            ("-mstm8", "STM8")
        ], required=False)

    options_MCS51 = forms.ChoiceField(
        choices=[
            BLANK_CHOICE_MCS51,
            ("--model-small", "Generate code for Small model programs. This is the default model."),
            ("--model-medium", "Generate code for Medium model programs."),
            ("--model-large", "Generate code for Large model programs."),
        ], required=False)

    options_Z80 = forms.ChoiceField(
        choices=[
            BLANK_CHOICE_Z80,
            ("--fno-omit-frame-pointer", "Never omit the frame pointer."),
            ("--callee-saves-bc", "Force a called function to always save BC."),
            ("--reserve-regs-iy", "This option tells the compiler that it is not allowed to use register "
                                  "pair iy. This option is incompatible with --fomit-frame-pointer.")
        ], required=False)

    options_STM8 = forms.ChoiceField(
        choices=[
            BLANK_CHOICE_STM8,
            ("--model-medium", "Generate code for Medium model programs. This is the default model."),
            ("--model-large", "Generate code for Large model programs.")
        ], required=False)

    standard.widget.attrs.update({"class": "form-control"})
    optimization.widget.attrs.update({"class": "form-control"})
    processor.widget.attrs.update({"class": "form-control"})
    options_MCS51.widget.attrs.update({"class": "form-control"})
    options_Z80.widget.attrs.update({"class": "form-control"})
    options_STM8.widget.attrs.update({"class": "form-control"})
