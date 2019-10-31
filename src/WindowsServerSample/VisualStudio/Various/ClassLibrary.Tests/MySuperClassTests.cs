using System;
using NUnit.Framework;

namespace MyClassLibrary.Tests
{
    [TestFixture]
    public class MySuperClassTest
    {
        private MySuperClass msc = new MySuperClass();

        [Test]
        public void TestEvenNumbers()
        {
            for (int i = 2; i < 100; i += 2)
            {
                Console.WriteLine($"Testing if {i} is even.");
                Assert.IsTrue(msc.IsEvenNumber(i));
            }
        }

        [Test]
        public void TestOdNumbers()
        {
            for (int i = 1; i < 100; i += 2)
            {
                Console.WriteLine($"Testing if {i} is NOT even.");
                Assert.IsFalse(msc.IsEvenNumber(i));
            }
        }
    }
}