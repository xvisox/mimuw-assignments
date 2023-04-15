from django.views import generic


class IndexView(generic.ListView):
    template_name = 'compiler/index.html'

    def get_queryset(self):
        return None
