function [x,l] = powermethod(A, l1, v1, tol, maxit)
iter = 0;

n = length(v1);
x = rand(n,1);
l = 1;
while iter < maxit
  iter = iter + 1;
  aux1 = A * x;
  if norm(aux1 - (l * x)) <= tol
    break
  end

  aux2 = l1 * (v1 * (v1' * x));
  x = aux1 - aux2;
  x = x / norm(x);
  l = x' * (A * x);
end


fprintf('Wykonano %d iteracji\n', iter);
end
