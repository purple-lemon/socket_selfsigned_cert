using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace PlainDotNetExample
{
    class Program
    {
        static void Main(string[] args)
        {
        }

        public class Point3d : IMovable<Point3d>, IGetDistance<Point3d>
		{
			public float X { get; set; }
			public float Y { get; set; }
			public float Z { get; set; }

			public double DistanceTo(Point3d p)
			{
				return Math.Sqrt((p.X - X) * (p.X - X) + (p.Y - Y) * (p.Y - Y) + (p.Z - Z) * (p.Z - Z));
			}

			public void Move(Point3d p)
			{
				this.X = p.X;
				this.Y = p.Y;
				this.Z = p.Z;
			}

			public override string ToString()
			{
				return string.Format("({0},{1},{2}", X, Y, Z);
			}
		}

		public interface IGetDistance<T>
		{
			double DistanceTo(T p);
		}

		public interface IMovable<T>
		{
			void Move(T p);
		}

		public class PointsSet
		{
			public List<Point3d> Points { get; set; }
			public void Add(Point3d point)
			{
				Points.Add(point);
			}

			public double Distance()
			{
				double distance = 0;
				for (var i = 0; i < Points.Count - 2; i++)
					distance += Points[i].DistanceTo(Points[i + 1]);
				return distance;
			}

			public override string ToString()
			{
				StringBuilder result = new StringBuilder();
				foreach (var p in Points)
					result.AppendLine("Point " + Points.IndexOf(p) + ": " +  p.ToString());

				return result.ToString();
			}

			public void Move()
			{

			}
		}

    }
}
