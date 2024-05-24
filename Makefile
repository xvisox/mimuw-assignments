all:
	swipl --goal=verify --stand_alone=true -o exec -c verify.pl

clean:
	rm exec