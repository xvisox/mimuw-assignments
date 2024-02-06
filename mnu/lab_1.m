function x = fullsolve(b,eps)
    function y = solvetridiag(A,B,C,b,N)
        y = zeros(N, 1);

        for i = 2:N
            factor = A(i) / B(i - 1);
            B(i) = B(i) - factor * C(i - 1);
            b(i) = b(i) - factor * b(i - 1);
        end

        y(N) = b(N) / B(N);
        for i = N - 1:-1:1
            y(i) = (b(i) - A(i) * y(i + 1)) / B(i);
        end
    end
N = length(b)
u = ones(N,1)
v = eps * ones(N,1)
sub = (1-eps)*ones(1,N)
main = (6-eps)*ones(1,N)
super = (1-eps)*ones(1,N)
res1 = solvetridiag(sub,main,super,b,N) % N x 1
aux1 = solvetridiag(sub,main,super,u,N) % N x 1
aux2 = v' * res1
upper = aux1 * aux2
lower = 1 + v' * aux1
x = res1 - (upper / lower)
end
