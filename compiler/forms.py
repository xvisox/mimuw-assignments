from django import forms
from compiler.models import Section


# todo: add directory uploading

class UploadFileForm(forms.Form):
    description = forms.CharField(max_length=100, required=False)
    file = forms.FileField()
    # todo: add parent choose field

    description.widget.attrs.update({"class": "form-control", "placeholder": "Description (optional)"})
    file.widget.attrs.update({"class": "form-control"})


class ChangeSectionsForm(forms.Form):
    start = forms.IntegerField(required=True)
    end = forms.IntegerField(required=True)
    sectionType = forms.ChoiceField(choices=Section.SectionType.choices, required=True)

    start.widget = start.hidden_widget()
    end.widget = end.hidden_widget()
    sectionType.widget.attrs.update({"class": "form-control"})


class CompileForm(forms.Form):
    BLANK_CHOICE = ("Default", "Select an option...")
    BLANK_CHOICE_MCS51 = ("Default", "Select an option for MCS51...")
    BLANK_CHOICE_Z80 = ("Default", "Select an option for Z80...")
    BLANK_CHOICE_STM8 = ("Default", "Select an option for STM8...")

    standard = forms.ChoiceField(
        choices=
        [BLANK_CHOICE, ("--std-c89", "C89"), ("--std-c99", "C99"), ("--std-c11", "C11")])

    optimization = forms.MultipleChoiceField(
        choices=
        [("--nolabelopt", "Will not optimize labels (makes the dumpfiles more readable)."),
         ("--noloopreverse", "Will not do loop reversal optimization."),
         ("--no-peep", "Disable peep-hole optimization with built-in rules."),
         ("--opt-code-speed",
          "The compiler will optimize code generation towards fast code, possibly at the expense of codesize.")
         ], required=False)

    processor = forms.ChoiceField(
        choices=
        [BLANK_CHOICE, ("-mmcs51", "MCS51"), ("-mz80", "Z80"), ("-mstm8", "STM8")])

    options_MCS51 = forms.ChoiceField(
        choices=
        [BLANK_CHOICE_MCS51,
         ("--model-small",
          "Generate code for Small model programs. This is the default model."),
         ("--model-medium", "Generate code for Medium model programs."),
         ("--model-large", "Generate code for Large model programs."),
         ])

    options_Z80 = forms.ChoiceField(
        choices=
        [BLANK_CHOICE_Z80,
         ("--fno-omit-frame-pointer", "Never omit the frame pointer."),
         ("--reserve-regs-iy",
          "This option tells the compiler that it is not allowed to use register "
          "pair iy. This option is incompatible with --fomit-frame-pointer."),
         ("--callee-saves-bc", "Force a called function to always save BC.")
         ])

    options_STM8 = forms.ChoiceField(
        choices=
        [BLANK_CHOICE_STM8,
         ("--model-medium", "Generate code for Medium model programs. This is the default model."),
         ("--model-large", "Generate code for Large model programs.")
         ])

    standard.widget.attrs.update({"class": "form-control"})
    optimization.widget.attrs.update({"class": "form-control"})
    processor.widget.attrs.update({"class": "form-control"})
    options_MCS51.widget.attrs.update({"class": "form-control"})
    options_Z80.widget.attrs.update({"class": "form-control"})
    options_STM8.widget.attrs.update({"class": "form-control"})
