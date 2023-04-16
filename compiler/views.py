from django.views import generic

from compiler.models import Directory


class IndexView(generic.ListView):
    template_name = 'compiler/index.html'

    def get_queryset(self):
        return None

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all user directories with no parent
        if self.request.user.is_authenticated:
            context['directories'] = Directory.objects.filter(info__owner=self.request.user, parent=None)
        else:
            context['directories'] = None
        return context


class EditView(generic.ListView):
    template_name = 'compiler/editor.html'

    def get_queryset(self):
        return None

    def get_context_data(self, *, object_list=None, **kwargs):
        context = super().get_context_data(**kwargs)
        # Get all user directories with no parent
        if self.request.user.is_authenticated:
            context['directories'] = Directory.objects.filter(info__owner=self.request.user, parent=None)
        else:
            context['directories'] = None
        return context
