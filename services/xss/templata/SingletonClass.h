/*
 Anti-XSS c-icap service
 SingletonClass.h
 Copyright (C) 2013  SYA-KE

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

//http://stackoverflow.com/questions/1008019/c-singleton-design-pattern

#ifndef SINGLETONCLASS_H_
#define SINGLETONCLASS_H_

namespace templata {

class SingletonClass {
    public:
        static SingletonClass& getInstance() {
            static SingletonClass instance; //Guaranteed to be destroyed.
            // Instantiated on first use.
            return instance;
        }
    private:
        SingletonClass() {}; // Constructor? (the {} brackets) are needed here.

        // Dont forget to declare these two. You want to make sure they
        // are unaccessable otherwise you may accidently get copies of
        // your singleton appearing.
        SingletonClass(SingletonClass const&); // Don't Implement
        void operator=(SingletonClass const&); // Don't implement
};

} /* namespace templata */
#endif /* SINGLETONCLASS_H_ */
