from django import forms


class UploadFileForm(forms.Form):
    description = forms.CharField(max_length=100, required=False)
    file = forms.FileField()

    description.widget.attrs.update({"class": "form-control", "placeholder": "Description (optional)"})
    file.widget.attrs.update({"class": "form-control"})
