dmsinject: dnsinject.cpp
	g++ dnsinject.cpp -o dnsinject -lpcap

clean:
	rm -f dnsinject
