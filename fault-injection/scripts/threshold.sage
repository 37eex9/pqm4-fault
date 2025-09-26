#!/usr/bin/env sage

import sys
from sage.all import *


class Calc_Threshold:
    """class to help calculation of the threshold function and its approximation
    """

    def __init__(self, r, d, t):
        # Parameter setzen
        self.r = r
        self.t = t
        self.d = d
        self.w = 2*d
        self.n = 2*r

        self.max_s = None  # maximaler wert von s bevor th(s) komplexwertig wird

        self.rho = [0] * (2 * self.w + 2)
        for l in range(0, 2 * self.w + 2):
            self.rho[l] = self.calc_rho(l)

        # calculate constant coefficients to avoid repeating calculation in loops
        self.X_coeff = self._x_coeff()
        self.B = log(self.t / (self.n - self.t), 2)
        self.pi0_coeff = self.d * (self.n - self.t)
        self.pi1_coeff = self.d * self.t

    def calc_rho(self, l):
        """compare to Section 5.3 Equation 5.1 in master thesis Fault attacks on BIKE
        """
        rho = (binomial(self.w, l) * binomial((self.n-self.w), (self.t-l))) / binomial(self.n, self.t)
        return rho

    def _x_coeff(self):
        """coefficient is static and does not need to be calculated for every s. So we call this method once on initialization and use the result in calc_X()
        """
        buff_a = 0
        buff_b = 0
        for l in range(0, self.w):
            buff_a = buff_a + 2*l*self.rho[2*l+1]
            buff_b = buff_b + self.rho[2*l+1]
        return buff_a / buff_b

    def calc_X(self, s):
        """compare to Section 5.3 Equation 5.1 in master thesis Fault attacks on BIKE
        """
        X = s * self.X_coeff
        return X

    def calc_pi0(self, s, X):
        """compare to Section 5.3 Equation 5.1 in master thesis Fault attacks on BIKE
        """
        pi_0 = ((self.w-1)*s- X) / self.pi0_coeff
        return pi_0

    def calc_pi1(self, s, X):
        """compare to Section 5.3 Equation 5.1 in master thesis Fault attacks on BIKE
        """
        pi_1 = (s+ X) / self.pi1_coeff
        return pi_1

    def calc_T(self, s):
        """compare to Section 5.3 Equation 5.1 in master thesis Fault attacks on BIKE
        """
        X = self.calc_X(s)
        pi_0 = self.calc_pi0(s, X)
        pi_1 = self.calc_pi1(s, X)
        if pi_1 > 1:
            T = self.d
            if self.max_s is None:
                self.max_s = s - 1
            return T, True
        else:
            A = self.d * log((1 - pi_1) / (1 - pi_0), 2)
            #B = log(e / (self.n - e), 2)
            C = log((1 - pi_1) / (1 - pi_0), 2)
            D = log(pi_0/pi_1, 2)
            T = ((A + self.B) / (C + D)).n() # zusammenfügen
            T = max(int(T) + 1, 0)#, (self.d + 1)/2)  # aufrunden und die untere Grenze setzen
            return T, False

    def s_boundarys(self):
        """gives the smallest and the largest value for s, which
        leads to a real (not complex) value for the threshold
        """
        l_bound = 1
        u_bound = self.r-1
        return l_bound, u_bound

    def plot(self, x, functions: list()):
        """plot a list of functions, each in the length of x.
        Expected order is 'exact threshold', 'approximation of the threshold', 'given approximation'

        Parameters
        ----------
        x : range of x axis
        functions : list of functions to plot
        """
        import matplotlib.pyplot as plt
        labels = ['exact threshold', 'approximation of the threshold', 'given approximation']

        for i,func in enumerate(functions):
            print(len(func))
            if len(x) == len(func):
                plt.plot(x, func, label= labels[i] if i < len(labels) else f"function{i}")

        plt.legend()
        plt.xlabel("|s|")
        plt.ylabel("Threshold(|s|)")
        plt.show()

    def compare(self, show=False):
        """calculates the exact threshold and an approximation and can plot them.

        Parameters
        ----------
        show : determines wether or not the functions are plotted

        returns the coefficients for the approximated function
        """
        if show: print("starting ...")
        l_bound, u_bound = self.s_boundarys()  # werte, für s, für die T nicht komplex wird
        thresholds = []
        my_approx = []
        given_aprx = []

        for s in range(l_bound, u_bound):
            th, done = self.calc_T(s)
            thresholds.append(th)
            if done:
                for i in range(s+1, u_bound):
                    thresholds.append(th)
                break

        #threshold Gerade berechnen
        if show: print(self.max_s)
        if self.max_s:
            a, b = var('a', 'b')
            eq1 = a + 1 * b == thresholds[0]  # Ergebnisse im Array beginnen bei s = 1 nicht 0, desshalb muss ich 1 abziehen
            eq2 = a + self.max_s * b == thresholds[self.max_s - 1]
            sol = solve([eq1, eq2], a, b, solution_dict=True)
            res_a = sol[0][a]
            res_b = sol[0][b]
            for s in range(l_bound, u_bound):
                my_approx.append(int(res_b * s + res_a))
            if show:
                print(res_a.n())
                print(res_b.n())
        else:
            print('could not calculate threshold')
            sys.exit()

        if show:
            print(f'Eine gute lineare Annäherung ist: {res_b.n()} * s + {res_a.n()}')
            self.plot(range(l_bound, u_bound), [thresholds, my_approx])

        return res_a.n(), res_b.n()


if __name__ == '__main__':
    if len(sys.argv) != 4:
        print("wrong number of arguments. Expects 3 arguments: r, d, t")
        exit()

    try:
        r = int(sys.argv[1])
        d = int(sys.argv[2])
        t = int(sys.argv[3])
    except ValueError:
        print("arguments can not be parsed as ints")
        exit()

    th = Calc_Threshold(r, t, d)
    th.compare(show=True)
